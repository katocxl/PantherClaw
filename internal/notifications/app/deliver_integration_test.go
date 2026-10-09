// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/notifications/adapters/smtpmail"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/notifications/smtptest"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// receiver is an https endpoint that answers from a script and records
// every request.
type receiver struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*recorded
	answers  []func(w http.ResponseWriter)
}

type recorded struct {
	header http.Header
	body   []byte
	host   string
}

func newReceiver(t *testing.T, answers ...func(w http.ResponseWriter)) *receiver {
	t.Helper()
	r := &receiver{answers: answers}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests = append(r.requests, &recorded{header: req.Header.Clone(), body: b, host: req.Host})
		n := len(r.requests)
		r.mu.Unlock()
		if n <= len(r.answers) {
			r.answers[n-1](w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) got() []*recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*recorded(nil), r.requests...)
}

func status(code int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// webhookEnv is a service that may reach 127.0.0.1 (as a self-hosted
// operator would allow) and trusts the test receiver's certificate.
func webhookEnv(t *testing.T, r *receiver) *env {
	t.Helper()
	e := newEnvConfig(t, napp.Config{PublicURL: "https://pc.example.test", AllowedPrivateRanges: loopback})
	pool := x509.NewCertPool()
	pool.AddCert(r.Certificate())
	e.svc.SetHTTPClient(httpx.NewEgressClient(httpx.EgressConfig{AllowedPrefixes: loopback, RootCAs: pool, Timeout: 5 * time.Second}))
	return e
}

func (e *env) delivery(t *testing.T) ids.UUID {
	t.Helper()
	var id ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.deliveries WHERE state = 'PENDING' ORDER BY created_at LIMIT 1").Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

type deliveryRow struct {
	state, lastError string
	attempts         int
	status           *int
}

func (e *env) row(t *testing.T, id ids.UUID) deliveryRow {
	t.Helper()
	var r deliveryRow
	var le *string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state, last_error, attempts, last_status FROM pc.deliveries WHERE id = $1", id).Scan(&r.state, &le, &r.attempts, &r.status)
	}); err != nil {
		t.Fatal(err)
	}
	if le != nil {
		r.lastError = *le
	}
	return r
}

// verify is an independent Standard Webhooks verifier (not domain.Sign):
// tolerance, then any matching v1 signature.
func verify(t *testing.T, secret string, h http.Header, body []byte) bool {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := strconv.ParseInt(h.Get("webhook-timestamp"), 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(h.Get("webhook-id") + "." + h.Get("webhook-timestamp") + "." + string(body)))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	for _, sig := range strings.Fields(h.Get("webhook-signature")) {
		if v, s, ok := strings.Cut(sig, ","); ok && v == "v1" && hmac.Equal([]byte(s), []byte(want)) {
			return true
		}
	}
	return false
}

func TestHR159_SignedWebhookRetriesUntilDelivered(t *testing.T) {
	r := newReceiver(t, status(500), status(503))
	e := webhookEnv(t, r)
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: r.URL + "/pc"})
	e.enqueue(t, napp.Message{
		Type: "security.credential_registered", Params: registered("alice@example.test"),
		Subject: &napp.Subject{Type: "webauthn_credential", ID: ids.NewV7()},
	})
	id := e.delivery(t)
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if err := e.svc.Deliver(ctx, e.org, id); err == nil {
			t.Fatalf("attempt %d: a 5xx was not retried", i)
		}
		if row := e.row(t, id); row.state != "PENDING" || row.attempts != i || row.status == nil || *row.status < 500 {
			t.Fatalf("after attempt %d: %+v", i, row)
		}
	}
	if err := e.svc.Deliver(ctx, e.org, id); err != nil {
		t.Fatal(err)
	}
	if row := e.row(t, id); row.state != "DELIVERED" || row.attempts != 3 {
		t.Fatalf("final %+v", row)
	}
	reqs := r.got()
	if len(reqs) != 3 {
		t.Fatalf("%d requests", len(reqs))
	}
	for _, q := range reqs {
		if !verify(t, hook.Secret, q.header, q.body) {
			t.Fatal("signature does not verify with the shown secret")
		}
		if q.header.Get("webhook-id") != reqs[0].header.Get("webhook-id") {
			t.Fatal("webhook-id changed between retries")
		}
	}
	if verify(t, "whsec_"+base64.StdEncoding.EncodeToString(make([]byte, 32)), reqs[0].header, reqs[0].body) {
		t.Fatal("another secret verifies")
	}
	var payload map[string]any
	if err := json.Unmarshal(reqs[2].body, &payload); err != nil {
		t.Fatal(err)
	}
	data, _ := payload["data"].(map[string]any)
	if payload["type"] != "security.credential_registered" || data["org"] != e.org.String() ||
		data["link"] != "https://pc.example.test/account?org="+e.org.String() || data["subject"] == nil {
		t.Fatalf("payload %s", reqs[2].body)
	}
	if _, ok := data["body"]; ok {
		t.Error("the webhook payload carries the free-text body")
	}
	// The channel is healthy again after the success.
	if n := e.count(t, "SELECT count(*) FROM pc.notification_channels WHERE id = $1 AND consecutive_failures = 0 AND last_success_at IS NOT NULL", hook.ID); n != 1 {
		t.Error("channel health was not reset by the success")
	}
}

func TestHR159_AttemptsAndExpiryAreBounded(t *testing.T) {
	r := newReceiver(t, status(500), status(500), status(500))
	e := webhookEnv(t, r)
	e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: r.URL + "/pc"})
	ctx := context.Background()

	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("a")})
	id := e.delivery(t)
	e.d.AdminExec(t, "UPDATE pc.deliveries SET attempts = 7 WHERE id = $1", id)
	if err := e.svc.Deliver(ctx, e.org, id); err != nil {
		t.Fatalf("the eighth attempt asks for another: %v", err)
	}
	if row := e.row(t, id); row.state != "FAILED" || row.attempts != 8 {
		t.Fatalf("after the last attempt %+v", row)
	}

	before := len(r.got())
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("b")})
	id = e.delivery(t)
	e.d.AdminExec(t, "UPDATE pc.notifications SET created_at = created_at - interval '1 hour', expires_at = created_at - interval '59 minutes'")
	if err := e.svc.Deliver(ctx, e.org, id); err != nil {
		t.Fatal(err)
	}
	if row := e.row(t, id); row.state != "EXPIRED" || len(r.got()) != before {
		t.Fatalf("expired notification: %+v, requests %d -> %d", row, before, len(r.got()))
	}
}

func TestHR159_RedirectsRateLimitsAndGoneEndpoints(t *testing.T) {
	r := newReceiver(t,
		func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://169.254.169.254/")
			w.WriteHeader(http.StatusFound)
		},
		func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		},
		status(http.StatusGone),
	)
	e := webhookEnv(t, r)
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: r.URL + "/pc"})
	e.channel(t, napp.NewChannel{Name: "ops-log", Kind: domain.KindLog, EventTypes: []string{"notification.*"}})
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("a")})
	id := e.delivery(t)
	ctx := context.Background()

	if err := e.svc.Deliver(ctx, e.org, id); err == nil || e.row(t, id).lastError != "redirect_refused" {
		t.Fatalf("redirect: %v %+v", err, e.row(t, id))
	}
	if len(r.got()) != 1 {
		t.Fatal("the redirect was followed")
	}
	var wait napp.RetryAfterError
	// Retry-After is a minimum: on the second attempt the schedule (5 min)
	// is already longer than the 2 minutes asked for.
	if err := e.svc.Deliver(ctx, e.org, id); !errors.As(err, &wait) || wait.Wait != 5*time.Minute {
		t.Fatalf("429: %v", err)
	}
	if err := e.svc.Deliver(ctx, e.org, id); err != nil {
		t.Fatalf("410: %v", err)
	}
	if row := e.row(t, id); row.state != "FAILED" || row.lastError != "gone" {
		t.Fatalf("after 410 %+v", row)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.notification_channels WHERE id = $1 AND state = 'PAUSED' AND pause_reason = 'GONE'", hook.ID); n != 1 {
		t.Fatal("a gone endpoint did not pause its channel")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.notifications WHERE type = 'notification.channel_paused'"); n != 1 {
		t.Error("the other channels were not told about the pause")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.notification.channel_paused'"); n != 1 {
		t.Error("the pause was not audited")
	}
	// Deliveries of a paused channel are skipped, not sent.
	e.enqueue(t, napp.Message{Type: "security.credential_removed", Params: registered("a")})
	if n := e.count(t, "SELECT count(*) FROM pc.deliveries WHERE channel_id = $1 AND state = 'SKIPPED'", hook.ID); n != 1 {
		t.Error("a paused channel received a pending delivery")
	}
}

func TestHR159_AChannelFailingFor72HoursIsPaused(t *testing.T) {
	r := newReceiver(t, status(500))
	e := webhookEnv(t, r)
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: r.URL + "/pc"})
	e.d.AdminExec(t, "UPDATE pc.notification_channels SET consecutive_failures = 40, failing_since = now() - interval '73 hours' WHERE id = $1", hook.ID)
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("a")})
	_ = e.svc.Deliver(context.Background(), e.org, e.delivery(t))
	if n := e.count(t, "SELECT count(*) FROM pc.notification_channels WHERE id = $1 AND state = 'PAUSED' AND pause_reason = 'FAILING'", hook.ID); n != 1 {
		t.Fatal("a channel failing for 72 hours was not paused")
	}
}

func TestHR157_WebhooksNeverReachPrivateAddressesAtDialTime(t *testing.T) {
	r := newReceiver(t)
	// The production egress client, without the operator's allowed range.
	e := newEnv(t)
	hook := e.channel(t, napp.NewChannel{Name: "siem", Kind: domain.KindWebhook, EventTypes: []string{"security.*"}, URL: "https://hooks.example.com/pc"})
	// The URL is changed behind validation's back to a name that resolves
	// to loopback (as DNS rebinding would): the dial-time check still holds.
	_, port, _ := net.SplitHostPort(r.Listener.Addr().String())
	e.d.AdminExec(t, "UPDATE pc.notification_channels SET url = $2 WHERE id = $1", hook.ID, "https://localhost:"+port+"/pc")
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("a")})
	id := e.delivery(t)
	if err := e.svc.Deliver(context.Background(), e.org, id); err == nil {
		t.Fatal("no retry after a denied destination")
	}
	if row := e.row(t, id); row.lastError != "destination_denied" || len(r.got()) != 0 {
		t.Fatalf("delivery %+v, %d requests reached the receiver", row, len(r.got()))
	}
}

func TestHR158_SlackGetsEscapedTextAndOneLink(t *testing.T) {
	r := newReceiver(t, status(200), func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "no_service")
	})
	e := newEnv(t)
	e.channel(t, napp.NewChannel{Name: "chat", Kind: domain.KindSlack, EventTypes: []string{"security.*"}, URL: "https://hooks.slack.com/services/T0/B0/XYZ"})
	// Reach the test receiver for hooks.slack.com (the test client skips
	// certificate checks; production uses the egress client).
	addr := r.Listener.Addr().String()
	e.svc.SetHTTPClient(&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}})
	e.enqueue(t, napp.Message{
		Type:   "security.credential_registered",
		Params: map[string]string{"user": "<https://evil.example|PantherClaw> & co", "key_name": "Desk key"},
	})
	id := e.delivery(t)
	if err := e.svc.Deliver(context.Background(), e.org, id); err != nil {
		t.Fatal(err)
	}
	req := r.got()[0]
	if req.host != "hooks.slack.com" {
		t.Fatalf("host %s", req.host)
	}
	var msg map[string]any
	if err := json.Unmarshal(req.body, &msg); err != nil {
		t.Fatal(err)
	}
	text, _ := msg["text"].(string)
	if strings.Contains(text, "<https://evil.example") || !strings.Contains(text, "&lt;https://evil.example|PantherClaw&gt; &amp; co") {
		t.Fatalf("text not escaped: %q", text)
	}
	if strings.Count(text, "<") != 1 || !strings.Contains(text, "<https://pc.example.test/account?org="+e.org.String()+"|Open in PantherClaw>") {
		t.Fatalf("text must hold exactly one link, to PantherClaw: %q", text)
	}
	for _, k := range []string{"blocks", "attachments"} {
		if _, ok := msg[k]; ok {
			t.Errorf("Slack message has %s (no actions allowed)", k)
		}
	}
	// A revoked Slack webhook pauses the channel.
	e.enqueue(t, napp.Message{Type: "security.credential_removed", Params: registered("a")})
	if err := e.svc.Deliver(context.Background(), e.org, e.delivery(t)); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.notification_channels WHERE state = 'PAUSED' AND pause_reason = 'GONE'"); n != 1 {
		t.Error("a revoked Slack webhook did not pause the channel")
	}
}

func TestHR155_EmailAndLogDeliveries(t *testing.T) {
	e := newEnv(t)
	e.channel(t, napp.NewChannel{Name: "ops-log", Kind: domain.KindLog, EventTypes: []string{"security.*"}})
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("alice@example.test"), Personal: []ids.UUID{e.alice}})
	ctx := context.Background()
	var email, logID ids.UUID
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, "SELECT id FROM pc.deliveries WHERE kind = 'email'").Scan(&email); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT id FROM pc.deliveries WHERE kind = 'log'").Scan(&logID)
	}); err != nil {
		t.Fatal(err)
	}
	// Without a relay, email is skipped, visibly.
	if err := e.svc.Deliver(ctx, e.org, email); err != nil {
		t.Fatal(err)
	}
	if row := e.row(t, email); row.state != "SKIPPED" || row.lastError != "email_not_configured" {
		t.Fatalf("email without a relay: %+v", row)
	}
	if err := e.svc.Deliver(ctx, e.org, logID); err != nil || e.row(t, logID).state != "DELIVERED" {
		t.Fatalf("log delivery: %v %+v", err, e.row(t, logID))
	}

	s := smtptest.New(t)
	host, port, _ := net.SplitHostPort(s.Addr)
	p, _ := strconv.Atoi(port)
	m, err := smtpmail.New(smtpmail.Config{
		Host: host, Port: p, TLS: smtpmail.TLSStartTLS, From: "pantherclaw@example.test",
		Username: s.User, Password: pclog.NewSecret([]byte(s.Password)), HeloName: "pc.example.test", RootCAs: s.RootCAs,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetMailer(m)
	e.enqueue(t, napp.Message{Type: "security.credential_removed", Params: registered("alice@example.test"), Personal: []ids.UUID{e.alice}})
	var next ids.UUID
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.deliveries WHERE kind = 'email' AND state = 'PENDING'").Scan(&next)
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Deliver(ctx, e.org, next); err != nil {
		t.Fatal(err)
	}
	msgs := s.Messages()
	if len(msgs) != 1 || msgs[0].To != "alice@example.test" || !msgs[0].TLS || !strings.Contains(msgs[0].Data, "never asks you to approve") {
		t.Fatalf("mail %+v", msgs)
	}
	if e.row(t, next).state != "DELIVERED" {
		t.Fatal("email not recorded as delivered")
	}
}
