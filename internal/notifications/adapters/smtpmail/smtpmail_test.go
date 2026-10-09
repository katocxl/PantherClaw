// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package smtpmail_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/notifications/adapters/smtpmail"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/smtptest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func mailer(t *testing.T, s *smtptest.Server, mode string) *smtpmail.Mailer {
	t.Helper()
	host, port, _ := net.SplitHostPort(s.Addr)
	p, _ := strconv.Atoi(port)
	m, err := smtpmail.New(smtpmail.Config{
		Host: host, Port: p, TLS: mode, From: "pantherclaw@example.test", Username: s.User,
		Password: pclog.NewSecret([]byte(s.Password)), HeloName: "pc.example.test", RootCAs: s.RootCAs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHR158_MailIsSentOverTLSAsPlainText(t *testing.T) {
	s := smtptest.New(t)
	m := mailer(t, s, smtpmail.TLSStartTLS)
	err := m.Send(context.Background(), napp.Mail{
		To: "alice@example.test", Subject: "A security key was added – check it", MessageID: "d-1",
		Body: "The security key \"Desk key\" was added.\nOpen PantherClaw: https://pc.example.test/account?org=x",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Messages()
	if len(got) != 1 {
		t.Fatalf("%d messages", len(got))
	}
	msg := got[0]
	if !msg.TLS || msg.User != s.User || msg.To != "alice@example.test" || msg.From != "pantherclaw@example.test" {
		t.Fatalf("envelope %+v", msg)
	}
	for _, want := range []string{
		"Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable",
		"Auto-Submitted: auto-generated", "Message-ID: <d-1@pc.example.test>", "Subject: =?utf-8?q?",
	} {
		if !strings.Contains(msg.Data, want) {
			t.Errorf("message lacks %q:\n%s", want, msg.Data)
		}
	}
	if strings.Contains(strings.ToLower(msg.Data), "content-type: text/html") {
		t.Error("HTML mail")
	}
}

func TestHR157_MailRefusesPlaintextAndInjection(t *testing.T) {
	s := smtptest.New(t)
	s.NoStartTLS = true // a relay (or an attacker on path) that hides STARTTLS
	if err := mailer(t, s, smtpmail.TLSStartTLS).Send(context.Background(), napp.Mail{To: "a@example.test", Subject: "x", Body: "y", MessageID: "1"}); err == nil {
		t.Fatal("sent without TLS")
	}
	if len(s.Messages()) != 0 {
		t.Fatal("a message reached the relay in plaintext")
	}
	s.NoStartTLS = false
	m := mailer(t, s, smtpmail.TLSStartTLS)
	for name, msg := range map[string]napp.Mail{
		"subject with CRLF":   {To: "a@example.test", Subject: "x\r\nBcc: victim@example.test", Body: "y", MessageID: "1"},
		"recipient with CRLF": {To: "a@example.test\r\nRCPT TO:<b@example.test>", Subject: "x", Body: "y", MessageID: "1"},
		"two recipients":      {To: "a@example.test, b@example.test", Subject: "x", Body: "y", MessageID: "1"},
	} {
		if err := m.Send(context.Background(), msg); !errors.Is(err, napp.ErrPermanent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := m.Send(context.Background(), napp.Mail{To: "refuse@example.test", Subject: "x", Body: "y", MessageID: "1"}); !errors.Is(err, napp.ErrPermanent) {
		t.Errorf("a 550 recipient is not permanent: %v", err)
	}
	for _, cfg := range []smtpmail.Config{
		{Host: "smtp.example.test", Port: 25, TLS: smtpmail.TLSNone, From: "pc@example.test", HeloName: "pc.example.test"},
		{Host: "smtp.example.test", Port: 587, TLS: "maybe", From: "pc@example.test", HeloName: "pc.example.test"},
		{Host: "smtp.example.test", Port: 587, TLS: smtpmail.TLSStartTLS, From: "not an address", HeloName: "pc.example.test"},
	} {
		if _, err := smtpmail.New(cfg); err == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
	if _, err := smtpmail.New(smtpmail.Config{Host: "127.0.0.1", Port: 1025, TLS: smtpmail.TLSNone, From: "pc@example.test", HeloName: "localhost"}); err != nil {
		t.Errorf("a loopback development relay: %v", err)
	}
}
