// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gateway is the PantherClaw gateway (G0 M6): the enforcement
// point between agents and their targets. It has no database access
// (ADR-0002). It proves which org it serves with a certificate from
// PantherClaw's internal CA and talks to the Authority over mutual TLS
// (HR-180, HR-181); workloads prove who they are with PAP/1, which the
// gateway forwards for the Authority to verify (HR-021).
package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Config is the pantherclaw-gateway configuration (JSON file + PC_GW_* env).
type Config struct {
	Log struct {
		Level string `json:"level" env:"PC_GW_LOG_LEVEL"`
	} `json:"log"`
	// Listen is the agent-facing address. Plain HTTP only on loopback;
	// otherwise set tls.cert_file and tls.key_file.
	Listen string `json:"listen" env:"PC_GW_LISTEN"`
	TLS    struct {
		CertFile string `json:"cert_file" env:"PC_GW_TLS_CERT_FILE"`
		KeyFile  string `json:"key_file" env:"PC_GW_TLS_KEY_FILE"`
	} `json:"tls"`
	// PublicURL is the base URL workloads call; request proofs are checked
	// against it, never against the Host header (PAP-1 §4).
	PublicURL string `json:"public_url" env:"PC_GW_PUBLIC_URL"`
	Control   struct {
		// APIURL is the server's public API, used only to enroll.
		APIURL string `json:"api_url" env:"PC_GW_CONTROL_API_URL"`
		// CASHA256 pins the internal CA ("sha256:<hex>", given with the
		// enrollment token).
		CASHA256 string `json:"ca_sha256" env:"PC_GW_CONTROL_CA_SHA256"`
		// GatewayURL overrides the gateway listener URL the server named at
		// enrollment.
		GatewayURL string `json:"gateway_url" env:"PC_GW_CONTROL_GATEWAY_URL"`
		// IdentityDir keeps the gateway's key and certificate (0700).
		IdentityDir string          `json:"identity_dir" env:"PC_GW_IDENTITY_DIR"`
		Timeout     config.Duration `json:"timeout" env:"PC_GW_CONTROL_TIMEOUT"`
	} `json:"control"`
	Target struct {
		// URL is the base URL of the payments target (scheme and host only).
		URL     string          `json:"url" env:"PC_GW_TARGET_URL"`
		Timeout config.Duration `json:"timeout" env:"PC_GW_TARGET_TIMEOUT"`
		// AllowedPrefixes re-allow private ranges for a local target, for
		// example 127.0.0.1/32 for pantherclaw-sim (HR-071, HR-077).
		AllowedPrefixes []string `json:"allowed_prefixes" env:"PC_GW_TARGET_ALLOWED_PREFIXES"`
	} `json:"target"`
}

// DefaultConfig returns development defaults.
func DefaultConfig() Config {
	var c Config
	c.Log.Level = "info"
	c.Listen = "127.0.0.1:8090"
	c.PublicURL = "http://127.0.0.1:8090"
	c.Control.APIURL = "http://127.0.0.1:8080"
	c.Control.IdentityDir = "deploy/dev/secrets/gateway"
	c.Control.Timeout = config.Duration(2 * time.Second)
	c.Target.Timeout = config.Duration(10 * time.Second)
	return c
}

var pinPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Validate implements config.Validator.
func (c *Config) Validate() error {
	var errs []error
	if _, ok := pclog.ParseLevel(c.Log.Level); !ok {
		errs = append(errs, errors.New("log.level must be debug, info, warn or error"))
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls.cert_file and tls.key_file must be set together"))
	}
	if c.TLS.CertFile == "" && !loopback(c.Listen) {
		errs = append(errs, errors.New("listen must be a loopback address unless tls.cert_file and tls.key_file are set"))
	}
	if c.Control.IdentityDir == "" {
		errs = append(errs, errors.New("control.identity_dir is required"))
	}
	if c.Control.CASHA256 != "" && !pinPattern.MatchString(c.Control.CASHA256) {
		errs = append(errs, errors.New("control.ca_sha256 must be sha256: and 64 hex digits"))
	}
	if c.Control.APIURL != "" {
		if u, err := baseURL(c.Control.APIURL); err != nil {
			errs = append(errs, fmt.Errorf("control.api_url: %w", err))
		} else if u.Scheme == "http" && !loopback(u.Host) {
			errs = append(errs, errors.New("control.api_url may use plain http only on loopback"))
		}
	}
	if c.Control.GatewayURL != "" {
		if u, err := baseURL(c.Control.GatewayURL); err != nil || u.Scheme != "https" {
			errs = append(errs, errors.New("control.gateway_url must be https://host[:port]"))
		}
	}
	if _, err := baseURL(c.Target.URL); err != nil {
		errs = append(errs, fmt.Errorf("target.url: %w", err))
	}
	if _, err := c.allowedPrefixes(); err != nil {
		errs = append(errs, err)
	}
	if c.Control.Timeout.D() <= 0 || c.Target.Timeout.D() <= 0 || c.Target.Timeout.D() > time.Minute {
		errs = append(errs, errors.New("timeouts must be positive (target at most 1m)"))
	}
	if _, err := baseURL(c.PublicURL); err != nil {
		errs = append(errs, fmt.Errorf("public_url: %w", err))
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
