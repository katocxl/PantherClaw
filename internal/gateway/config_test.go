// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import "testing"

const (
	testOrg   = "01920000-0000-7000-8000-0000000000a1"
	testAgent = "01920000-0000-7000-8000-0000000000c1" // the instance id
	testEnv   = "01920000-0000-7000-8000-0000000000e1"
	testPin   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

func TestConfigValidation(t *testing.T) {
	base := DefaultConfig()
	base.Target.URL = "http://127.0.0.1:9090"
	base.Control.CASHA256 = testPin
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"public listen without TLS": func(c *Config) { c.Listen = "0.0.0.0:8090" },
		"half a TLS pair":           func(c *Config) { c.TLS.CertFile = "cert.pem" },
		"http api off loopback":     func(c *Config) { c.Control.APIURL = "http://10.0.0.5:8080" },
		"api path":                  func(c *Config) { c.Control.APIURL = "http://127.0.0.1:8080/api" },
		"plain gateway url":         func(c *Config) { c.Control.GatewayURL = "http://127.0.0.1:8443" },
		"bad pin":                   func(c *Config) { c.Control.CASHA256 = "sha256:abc" },
		"no identity dir":           func(c *Config) { c.Control.IdentityDir = "" },
		"target userinfo":           func(c *Config) { c.Target.URL = "http://u:p@127.0.0.1:9090" },
		"target scheme":             func(c *Config) { c.Target.URL = "ftp://127.0.0.1" },
		"bad prefix":                func(c *Config) { c.Target.AllowedPrefixes = []string{"127.0.0.1"} },
		"no public url":             func(c *Config) { c.PublicURL = "" },
		"public url path":           func(c *Config) { c.PublicURL = "http://127.0.0.1:8090/gw" },
	} {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tlsListen := base
	tlsListen.Listen, tlsListen.TLS.CertFile, tlsListen.TLS.KeyFile = "0.0.0.0:8090", "cert.pem", "key.pem"
	if err := tlsListen.Validate(); err != nil {
		t.Fatalf("a TLS listener on a public address refused: %v", err)
	}
}
