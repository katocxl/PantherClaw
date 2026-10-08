// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gateway is the walking-skeleton PantherClaw gateway (M1.5): one
// hard-coded route, POST /v1/refunds, that turns a request into ActionIR,
// asks the Transaction Authority, verifies the permit, commits to dispatch
// and sends a re-serialized request to the target. It has no database access
// (ADR-0002). Workload identity comes from DEVELOPMENT-ONLY headers until
// PAP/1 (M3); authority authentication is the dev gateway token until mTLS
// (M6).
package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// DevEnv is the placeholder environment of every dev action until
// environments exist (M2).
const DevEnv = "01920000-0000-7000-8000-0000000000e1"

// Config is the pantherclaw-gateway configuration (JSON file + PC_GW_* env).
type Config struct {
	Log struct {
		Level string `json:"level" env:"PC_GW_LOG_LEVEL"`
	} `json:"log"`
	// Listen must be a loopback address: dev workload headers are trusted.
	Listen    string `json:"listen" env:"PC_GW_LISTEN"`
	GatewayID string `json:"gateway_id" env:"PC_GW_ID"`
	Org       string `json:"org" env:"PC_GW_ORG"`
	Authority struct {
		URL       string          `json:"url" env:"PC_GW_AUTHORITY_URL"`
		TokenFile string          `json:"token_file" env:"PC_GW_AUTHORITY_TOKEN_FILE"`
		Timeout   config.Duration `json:"timeout" env:"PC_GW_AUTHORITY_TIMEOUT"`
	} `json:"authority"`
	Target struct {
		// URL is the base URL of the payments target (scheme and host only).
		URL     string          `json:"url" env:"PC_GW_TARGET_URL"`
		Timeout config.Duration `json:"timeout" env:"PC_GW_TARGET_TIMEOUT"`
		// AllowedPrefixes re-allow private ranges for a local target, for
		// example 127.0.0.1/32 for pantherclaw-sim (HR-071, HR-077).
		AllowedPrefixes []string `json:"allowed_prefixes" env:"PC_GW_TARGET_ALLOWED_PREFIXES"`
	} `json:"target"`
	// DevWorkloads lists the agent instance ids accepted in PC-Dev-Workload.
	DevWorkloads []string `json:"dev_workloads" env:"PC_GW_DEV_WORKLOADS"`
}

// DefaultConfig returns development defaults.
func DefaultConfig() Config {
	var c Config
	c.Log.Level = "info"
	c.Listen = "127.0.0.1:8090"
	c.GatewayID = "gw-dev-1"
	c.Authority.URL = "http://127.0.0.1:8080"
	c.Authority.Timeout = config.Duration(2 * time.Second)
	c.Target.Timeout = config.Duration(10 * time.Second)
	return c
}

// Validate implements config.Validator.
func (c *Config) Validate() error {
	var errs []error
	if _, ok := pclog.ParseLevel(c.Log.Level); !ok {
		errs = append(errs, errors.New("log.level must be debug, info, warn or error"))
	}
	if !loopback(c.Listen) {
		errs = append(errs, errors.New("listen must be a loopback address (dev workload headers are development-only)"))
	}
	if c.GatewayID == "" {
		errs = append(errs, errors.New("gateway_id is required"))
	}
	if _, err := ids.Parse[ids.Org](c.Org); err != nil {
		errs = append(errs, errors.New("org must be the org id printed by `pantherclaw-server dev seed`"))
	}
	if u, err := baseURL(c.Authority.URL); err != nil {
		errs = append(errs, fmt.Errorf("authority.url: %w", err))
	} else if u.Scheme == "http" && !loopback(u.Host) {
		errs = append(errs, errors.New("authority.url may use plain http only on loopback"))
	}
	if c.Authority.TokenFile == "" {
		errs = append(errs, errors.New("authority.token_file is required"))
	}
	if _, err := baseURL(c.Target.URL); err != nil {
		errs = append(errs, fmt.Errorf("target.url: %w", err))
	}
	if _, err := c.allowedPrefixes(); err != nil {
		errs = append(errs, err)
	}
	if c.Authority.Timeout.D() <= 0 || c.Target.Timeout.D() <= 0 || c.Target.Timeout.D() > time.Minute {
		errs = append(errs, errors.New("timeouts must be positive (target at most 1m)"))
	}
	if len(c.DevWorkloads) == 0 {
		errs = append(errs, errors.New("dev_workloads must list at least one agent instance id"))
	}
	for _, w := range c.DevWorkloads {
		if _, err := ids.ParseUUID(w); err != nil {
			errs = append(errs, fmt.Errorf("dev_workloads: %q is not a UUID", w))
		}
	}
	return errors.Join(errs...)
}

func (c *Config) allowedPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Target.AllowedPrefixes))
	for _, s := range c.Target.AllowedPrefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("target.allowed_prefixes: %q is not a CIDR prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// baseURL accepts only scheme://host[:port] with no path, query or userinfo.
func baseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return nil, errors.New("does not parse")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("scheme must be http or https")
	case u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("must be scheme://host[:port] only")
	}
	u.Path = ""
	return u, nil
}

func loopback(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}
