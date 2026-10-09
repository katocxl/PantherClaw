// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package smtptest is an in-process SMTP relay for tests: EHLO, STARTTLS
// (with a self-signed certificate for 127.0.0.1), AUTH PLAIN, MAIL, RCPT,
// DATA and QUIT. It records every message and whether it arrived over TLS.
// A recipient whose address starts with "refuse" is rejected with 550.
package smtptest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Message is one received message.
type Message struct {
	From, To string
	Data     string
	TLS      bool
	User     string
}

// Server is a running relay.
type Server struct {
	Addr string
	// RootCAs trusts the server's certificate.
	RootCAs *x509.CertPool
	// NoStartTLS stops advertising STARTTLS (a downgrade attempt).
	NoStartTLS bool
	// User and Password are the accepted credentials.
	User, Password string

	ln  net.Listener
	tls *tls.Config

	mu       sync.Mutex
	messages []Message
}

// New starts a relay on 127.0.0.1; it stops when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Addr: ln.Addr().String(), RootCAs: pool, User: "pantherclaw", Password: "relay-test-password", ln: ln,
		tls: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12},
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Messages returns the received messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(c)
	}
}

func (s *Server) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	reply := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}
	reply("220 smtptest ready")
	var msg Message
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			lines := []string{"250-smtptest", "250-AUTH PLAIN"}
			if !s.NoStartTLS && !secure {
				lines = append(lines, "250-STARTTLS")
			}
			lines = append(lines, "250 8BITMIME")
			for _, l := range lines {
				_, _ = w.WriteString(l + "\r\n")
			}
			_ = w.Flush()
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(conn, s.tls)
			hctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := tc.HandshakeContext(hctx)
			cancel()
			if err != nil {
				return
			}
			conn, secure = tc, true
			r, w = bufio.NewReader(conn), bufio.NewWriter(conn)
		case "AUTH":
			parts := strings.Fields(line)
			if len(parts) != 3 || !strings.EqualFold(parts[1], "PLAIN") {
				reply("504 unsupported")
				continue
			}
			raw, _ := base64.StdEncoding.DecodeString(parts[2])
			creds := strings.Split(string(raw), "\x00")
			if len(creds) != 3 || creds[1] != s.User || creds[2] != s.Password {
				reply("535 authentication failed")
				continue
			}
			msg.User = creds[1]
			reply("235 ok")
		case "MAIL":
			msg.From = addr(line)
			reply("250 ok")
		case "RCPT":
			to := addr(line)
			if strings.HasPrefix(to, "refuse") {
				reply("550 no such user")
				continue
			}
			msg.To = to
			reply("250 ok")
		case "DATA":
			reply("354 end with .")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			msg.Data, msg.TLS = b.String(), secure
			s.mu.Lock()
			s.messages = append(s.messages, msg)
			s.mu.Unlock()
			msg = Message{User: msg.User}
			reply("250 queued")
		case "RSET", "NOOP":
			reply("250 ok")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 not implemented")
		}
	}
}

func addr(line string) string {
	i, j := strings.Index(line, "<"), strings.LastIndex(line, ">")
	if i < 0 || j < i {
		return ""
	}
	return line[i+1 : j]
}
