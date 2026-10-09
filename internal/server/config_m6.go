// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"net"
	"net/url"
	"slices"
)

// GatewayAPIConfig is the server's listener for gateways (G0 M6, HR-181):
// TLS 1.3 with a client certificate from the internal CA required on every
// connection. AuthorityService and GatewayService (except Enroll) are
// served only there. Without an address the listener is off and no gateway
// can authenticate.
type GatewayAPIConfig struct {
	// Addr is where gateways connect, for example 0.0.0.0:8443.
	Addr string `json:"addr" env:"PC_GATEWAY_API_ADDR"`
	// Hostnames are the DNS names or IP addresses in the listener's
	// certificate.
	Hostnames []string `json:"hostnames" env:"PC_GATEWAY_API_HOSTNAMES"`
	// URL is what gateways are told to use: https://<one of hostnames>[:port].
	URL string `json:"url" env:"PC_GATEWAY_API_URL"`
}

func (c *Config) validateM6() []error {
	g := c.GatewayAPI
	if g.Addr == "" {
		if len(g.Hostnames) != 0 || g.URL != "" {
			return []error{errors.New("gateway_api: hostnames and url need gateway_api.addr")}
		}
		return nil
	}
	var errs []error
	if _, _, err := net.SplitHostPort(g.Addr); err != nil {
		errs = append(errs, errors.New("gateway_api.addr must be host:port"))
	}
	if len(g.Hostnames) == 0 || len(g.Hostnames) > 16 {
		errs = append(errs, errors.New("gateway_api.hostnames must name 1 to 16 hosts"))
	}
	u, err := url.Parse(g.URL)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "":
		errs = append(errs, errors.New("gateway_api.url must be https://host[:port]"))
	case !slices.Contains(g.Hostnames, u.Hostname()):
		errs = append(errs, errors.New("gateway_api.url's host must be one of gateway_api.hostnames"))
	}
	return errs
}
