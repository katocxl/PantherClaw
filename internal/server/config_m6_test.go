// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

func TestGatewayAPIConfigIsValidated(t *testing.T) {
	cases := map[string]struct {
		cfg GatewayAPIConfig
		ok  bool
	}{
		"off":                    {GatewayAPIConfig{}, true},
		"on":                     {GatewayAPIConfig{Addr: "0.0.0.0:8443", Hostnames: []string{"gw.example.com"}, URL: "https://gw.example.com:8443"}, true},
		"names without listener": {GatewayAPIConfig{Hostnames: []string{"gw.example.com"}}, false},
		"no names":               {GatewayAPIConfig{Addr: "0.0.0.0:8443", URL: "https://gw.example.com:8443"}, false},
		"plain http url":         {GatewayAPIConfig{Addr: "0.0.0.0:8443", Hostnames: []string{"gw.example.com"}, URL: "http://gw.example.com:8443"}, false},
		"url host not a name":    {GatewayAPIConfig{Addr: "0.0.0.0:8443", Hostnames: []string{"gw.example.com"}, URL: "https://other.example.com"}, false},
		"url with a path":        {GatewayAPIConfig{Addr: "0.0.0.0:8443", Hostnames: []string{"gw.example.com"}, URL: "https://gw.example.com/x"}, false},
		"bad address":            {GatewayAPIConfig{Addr: "8443", Hostnames: []string{"gw.example.com"}, URL: "https://gw.example.com"}, false},
	}
	for name, c := range cases {
		cfg := Config{GatewayAPI: c.cfg}
		if errs := cfg.validateM6(); (len(errs) == 0) != c.ok {
			t.Errorf("%s: %v", name, errs)
		}
	}
}
