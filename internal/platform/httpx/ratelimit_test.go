// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func req(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/oauth2/token", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestTrustedProxyClientIP(t *testing.T) {
	f := TrustedProxyClientIP([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	for name, tc := range map[string]struct {
		remote string
		xff    []string
		want   string
	}{
		"direct client":                {"203.0.113.7:5000", nil, "203.0.113.7"},
		"untrusted peer spoofs header": {"203.0.113.7:5000", []string{"198.51.100.1"}, "203.0.113.7"},
		"trusted proxy":                {"10.0.0.2:443", []string{"198.51.100.1"}, "198.51.100.1"},
		"client prepends a fake hop":   {"10.0.0.2:443", []string{"1.1.1.1, 198.51.100.1"}, "198.51.100.1"},
		"two trusted proxies":          {"10.0.0.2:443", []string{"198.51.100.1, 10.1.1.1"}, "198.51.100.1"},
		"split headers":                {"10.0.0.2:443", []string{"198.51.100.1", "10.9.9.9"}, "198.51.100.1"},
		"malformed hop":                {"10.0.0.2:443", []string{"198.51.100.1, nonsense"}, "10.0.0.2"},
		"no header from proxy":         {"10.0.0.2:443", nil, "10.0.0.2"},
		"only proxies in header":       {"10.0.0.2:443", []string{"10.3.3.3"}, "10.0.0.2"},
		"ipv6 loopback proxy":          {"[::1]:443", []string{"2001:db8::5"}, "2001:db8::5"},
	} {
		if got := f(req(tc.remote, tc.xff...)); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	if got := ClientIP(req("10.0.0.2:443", "198.51.100.1")); got != "10.0.0.2" {
		t.Errorf("ClientIP must ignore forwarding headers: %q", got)
	}
}

func TestLimiterKeysClientsBehindAProxySeparately(t *testing.T) {
	l := NewLimiter(1, 60e9, nil).WithClientIP(TrustedProxyClientIP([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}))
	a, b := req("10.0.0.2:1", "198.51.100.1"), req("10.0.0.2:2", "198.51.100.2")
	if !l.AllowRequest(a) || !l.AllowRequest(b) {
		t.Fatal("two clients behind one proxy share a key")
	}
	if l.AllowRequest(a) {
		t.Fatal("limit not applied per client")
	}
}
