// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"net"
	"net/http"
	"slices"
	"strings"
)

// Bound reports whether a request URL's host may receive the credential:
// an allowed "host" entry matches any port of that host, a "host:port"
// entry only that port. Hosts compare case-insensitively.
func Bound(allowedHosts []string, rawHost, defaultPort string) bool {
	host, port, err := net.SplitHostPort(rawHost)
	if err != nil {
		host, port = rawHost, defaultPort
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	return slices.ContainsFunc(allowedHosts, func(entry string) bool {
		h, p, err := net.SplitHostPort(entry)
		if err != nil {
			h, p = entry, ""
		}
		h = strings.ToLower(strings.Trim(h, "[]"))
		return h == host && (p == "" || p == port)
	})
}

// Place sets the credential on the request: "Header: [Scheme ]secret".
// It refuses a request whose host the credential is not bound to, before
// anything is sent (HR-060).
func Place(r *http.Request, allowedHosts []string, header, scheme string, secret []byte) error {
	port := "443"
	if r.URL.Scheme == "http" {
		port = "80"
	}
	if !Bound(allowedHosts, r.URL.Host, port) {
		return ErrNotBound
	}
	v := string(secret)
	if scheme != "" {
		v = scheme + " " + v
	}
	r.Header.Set(header, v)
	return nil
}
