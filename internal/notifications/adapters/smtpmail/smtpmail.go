// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package smtpmail sends notification email through an operator-configured
// SMTP relay (G0 M5 part 1, decision 16 of the brief). TLS is required:
// implicit TLS or STARTTLS, at least TLS 1.2, with the certificate verified;
// plaintext is allowed only to a relay on a loopback address (local
// development). Messages are text/plain UTF-8, quoted-printable, marked
// Auto-Submitted, and every header value is checked for CR and LF.
package smtpmail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TLS modes.
const (
	TLSImplicit = "implicit"
	TLSStartTLS = "starttls"
	// TLSNone is allowed only for a loopback relay.
	TLSNone = "none"
)

// Config is the relay configuration (operator only).
type Config struct {
	Host     string
	Port     int
	TLS      string
	From     string
	Username string
	Password pclog.Secret[[]byte]
	// HeloName is sent in EHLO and used in Message-ID (the public host).
	HeloName string
	// RootCAs overrides the system roots (a private relay, tests).
	RootCAs *x509.CertPool
	// Timeout bounds one message; default 30 s.
	Timeout time.Duration
}

// Mailer sends mail through one relay.
type Mailer struct {
	cfg  Config
	from string
}

// New validates cfg.
func New(cfg Config) (*Mailer, error) {
	var errs []error
	if cfg.Host == "" || cfg.Port < 1 || cfg.Port > 65535 {
		errs = append(errs, errors.New("host and port are required"))
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil || strings.ContainsAny(cfg.From, "\r\n") {
		errs = append(errs, errors.New("from must be one email address"))
	}
	switch cfg.TLS {
	case TLSImplicit, TLSStartTLS:
	case TLSNone:
		if !loopback(cfg.Host) {
			errs = append(errs, errors.New("plaintext SMTP is allowed only to a loopback relay"))
		}
	default:
		errs = append(errs, errors.New(`tls must be "implicit" or "starttls"`))
	}
	if cfg.HeloName == "" || strings.ContainsAny(cfg.HeloName, " \r\n<>@") {
		errs = append(errs, errors.New("helo name is required (the public host)"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("smtp: %w", err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Mailer{cfg: cfg, from: from.Address}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (m *Mailer) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: m.cfg.RootCAs}
}

// Send delivers one message. A recipient or message the relay refuses
// permanently (5xx) returns an error wrapping napp.ErrPermanent.
func (m *Mailer) Send(ctx context.Context, msg napp.Mail) error {
	to, err := mail.ParseAddress(msg.To)
	if err != nil || strings.ContainsAny(msg.To, "\r\n") {
		return fmt.Errorf("smtp: recipient: %w", napp.ErrPermanent)
	}
	if strings.ContainsAny(msg.Subject+msg.MessageID, "\r\n") {
		return fmt.Errorf("smtp: header value with a line break: %w", napp.ErrPermanent)
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if m.cfg.TLS == TLSImplicit {
		tc := tls.Client(conn, m.tlsConfig())
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("smtp: tls: %w", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp: greeting: %w", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(m.cfg.HeloName); err != nil {
		return fmt.Errorf("smtp: ehlo: %w", err)
	}
	if m.cfg.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: the relay does not offer STARTTLS; refusing to send in plaintext")
		}
		if err := c.StartTLS(m.tlsConfig()); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, string(m.cfg.Password.Reveal()), m.cfg.Host)); err != nil {
			return fmt.Errorf("smtp: auth: %w", classify(err))
		}
	}
	if err := c.Mail(m.from); err != nil {
		return fmt.Errorf("smtp: mail from: %w", classify(err))
	}
	if err := c.Rcpt(to.Address); err != nil {
		return fmt.Errorf("smtp: rcpt: %w", classify(err))
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", classify(err))
	}
	if _, err := w.Write(m.message(to.Address, msg)); err != nil {
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: end of data: %w", classify(err))
	}
	return c.Quit()
}

// classify marks permanent (5xx) replies.
func classify(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return errors.Join(err, napp.ErrPermanent)
	}
	return err
}

// message builds the RFC 5322 message.
func (m *Mailer) message(to string, msg napp.Mail) []byte {
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", "PantherClaw <"+m.from+">")
	h("To", "<"+to+">")
	h("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+msg.MessageID+"@"+m.cfg.HeloName+">")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	h("X-Auto-Response-Suppress", "All")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(msg.Body, "\n", "\r\n")))
	_ = qp.Close()
	return b.Bytes()
}

var _ napp.Mailer = (*Mailer)(nil)
