// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import "testing"

const (
	testOrg   = "01920000-0000-7000-8000-0000000000a1"
	testAgent = "01920000-0000-7000-8000-0000000000c1" // the instance id
	testEnv   = "01920000-0000-7000-8000-0000000000e1"
)

func TestConfigValidation(t *testing.T) {
	base := DefaultConfig()
	base.Org = testOrg
	base.Authority.TokenFile, base.Target.URL = "t", "http://127.0.0.1:9090"
	if err := base.Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"public listen":   func(c *Config) { c.Listen = "0.0.0.0:8090" },
		"no org":          func(c *Config) { c.Org = "" },
		"http authority":  func(c *Config) { c.Authority.URL = "http://10.0.0.5:8080" },
		"authority path":  func(c *Config) { c.Authority.URL = "http://127.0.0.1:8080/api" },
		"target userinfo": func(c *Config) { c.Target.URL = "http://u:p@127.0.0.1:9090" },
		"target scheme":   func(c *Config) { c.Target.URL = "ftp://127.0.0.1" },
		"bad prefix":      func(c *Config) { c.Target.AllowedPrefixes = []string{"127.0.0.1"} },
		"no public url":   func(c *Config) { c.PublicURL = "" },
		"public url path": func(c *Config) { c.PublicURL = "http://127.0.0.1:8090/gw" },
		"no token":        func(c *Config) { c.Authority.TokenFile = "" },
	} {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
