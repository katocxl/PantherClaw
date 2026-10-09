// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrDestinationDenied reports a connection to a forbidden address (HR-071).
var ErrDestinationDenied = errors.New("httpx: destination address denied")

// deniedPrefixes are never reachable from egress clients unless a prefix is
// explicitly allowed (customer-hosted gateways, HR-077). Cloud metadata
// endpoints fall inside the link-local, CGNAT and ULA ranges.
var deniedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network", incl. 0.0.0.0
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT (incl. 100.100.100.200 metadata)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local (incl. 169.254.169.254 metadata)
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"192.88.99.0/24",  // 6to4 relay anycast
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, incl. 255.255.255.255
	"::/128",          // unspecified
	"::1/128",         // loopback
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard
	"2001:db8::/32",   // documentation
	"fc00::/7",        // unique local (incl. fd00:ec2::254 metadata)
	"fe80::/10",       // link-local
	"ff00::/8",        // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// embeddedIPv4 returns IPv4 addresses that an IPv6 address carries and that
// routers or stacks may translate to (IPv4-mapped, NAT64, 6to4, Teredo).
func embeddedIPv4(a netip.Addr) []netip.Addr {
	if !a.Is6() {
		return nil
	}
	b := a.As16()
	var out []netip.Addr
	switch {
	case a.Is4In6():
		out = append(out, a.Unmap())
	case netip.MustParsePrefix("64:ff9b::/96").Contains(a):
		out = append(out, netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	case netip.MustParsePrefix("2002::/16").Contains(a):
		out = append(out, netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	case netip.MustParsePrefix("2001::/32").Contains(a): // Teredo: client IPv4 is inverted
		out = append(out, netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}))
	}
	return out
}

// DeniedAddr reports whether a is forbidden as an egress destination, given
// explicitly allowed prefixes. Cloud metadata endpoints are denied even
// inside an allowed prefix (HR-077).
func DeniedAddr(a netip.Addr, allowed []netip.Prefix) bool {
	a = a.WithZone("")
	if MetadataAddr(a) {
		return true
	}
	for _, p := range allowed {
		if p.Contains(a) {
			return false
		}
	}
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return true
	}
	for _, p := range deniedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	for _, v4 := range embeddedIPv4(a) {
		if DeniedAddr(v4, allowed) {
			return true
		}
	}
	return false
}

// EgressConfig configures an egress client.
type EgressConfig struct {
	// Timeout bounds a whole request; default 10 s.
	Timeout time.Duration
	// AllowedPrefixes re-allows otherwise denied ranges. Only customer-hosted
	// gateways may set it, for their own private targets (HR-077).
	AllowedPrefixes []netip.Prefix
	// RootCAs overrides the system roots (private CAs, tests).
	RootCAs *x509.CertPool
}

// NewEgressClient returns the only kind of HTTP client allowed to reach
// targets (HR-070..074):
//   - redirects are never followed (HR-070);
//   - the IP actually connected to, after DNS resolution, is checked at dial
//     time, so DNS rebinding and alternative IP spellings cannot bypass the
//     deny list (HR-071);
//   - HTTP(S)_PROXY and NO_PROXY are ignored (HR-072);
//   - no client certificate is ever presented: the gateway's mTLS identity
//     never leaves on egress (HR-074);
//   - transparent decompression is off; callers apply size and ratio caps.
func NewEgressClient(cfg EgressConfig) *http.Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	allowed := append([]netip.Prefix(nil), cfg.AllowedPrefixes...)
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: unparsable address", ErrDestinationDenied)
			}
			if DeniedAddr(ap.Addr(), allowed) {
				return fmt.Errorf("%w: %s", ErrDestinationDenied, ap.Addr())
			}
			return nil
		},
	}
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Never present a client certificate, whatever the server asks.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
	}
	if cfg.RootCAs != nil {
		tlsConf.RootCAs = cfg.RootCAs
	}
	transport := &http.Transport{
		Proxy:                  nil, // HR-072: never from the environment
		DialContext:            dialer.DialContext,
		TLSClientConfig:        tlsConf,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    10,
		IdleConnTimeout:        90 * time.Second,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // HR-070
		},
	}
}
