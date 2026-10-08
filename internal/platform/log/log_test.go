// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package log

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const canary = "s3cr3t-CANARY-value-7f1d"

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return New(buf, Options{Service: "test-svc", Version: "v0.0.0-test", Level: slog.LevelDebug})
}

// records parses every output line as one JSON object.
func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not a JSON object: %v\n%s", err, line)
		}
		out = append(out, m)
	}
	return out
}

type creds struct {
	User     string
	Password Secret[string]
	token    Secret[string]
	Email    Sensitive[string]
}

func TestT041_SecretsNeverReachLogOutput(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	c := creds{User: "alice", Password: NewSecret(canary), token: NewSecret(canary), Email: NewSensitive(canary)}
	ctx := context.Background()

	l.InfoContext(ctx, "auth.login", slog.Any("secret_value", NewSecret(canary)))
	l.InfoContext(ctx, "auth.login", slog.Any("creds", c))
	l.InfoContext(ctx, "auth.login", "creds", c)
	l.InfoContext(ctx, "auth.login", slog.Any("ptr", &c))
	l.InfoContext(ctx, "auth.login", slog.String("Authorization", "Bearer "+canary))
	l.InfoContext(ctx, "auth.login", slog.String("X-Api-Key", canary))
	l.InfoContext(ctx, "auth.login", slog.String("set-cookie", "s="+canary))
	l.InfoContext(ctx, "auth.login", slog.String("client_secret", canary))
	l.InfoContext(ctx, "auth.login", slog.String("access_token", canary))
	l.InfoContext(ctx, "auth.login", slog.String("pap_proof", canary))
	l.InfoContext(ctx, "auth.login", slog.String("database_dsn", "postgres://u:"+canary+"@h/db"))
	l.InfoContext(ctx, "auth.login", slog.Group("http", slog.String("authorization", canary)))
	l.InfoContext(ctx, "auth.login", slog.Group("token", slog.String("value", canary)))
	l.InfoContext(ctx, "auth.login", slog.Any("headers", map[string]string{"Authorization": canary, "Accept": "x"}))
	l.InfoContext(ctx, "auth.login", slog.Any("nested", map[string]any{"a": map[string]string{"private_key": canary}}))
	l.With(slog.String("api_key", canary)).InfoContext(ctx, "auth.login")
	l.WithGroup("g").InfoContext(ctx, "auth.login", slog.String("password", canary))

	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("secret canary leaked into log output:\n%s", out)
	}
	if got := len(records(t, &buf)); got != 17 {
		t.Fatalf("got %d records, want 17", got)
	}
	if !strings.Contains(out, Redacted) {
		t.Fatal("expected redaction markers in output")
	}
}

func TestT041_SecretsNeverReachFmtOrJSON(t *testing.T) {
	c := creds{User: "alice", Password: NewSecret(canary), token: NewSecret(canary), Email: NewSensitive(canary)}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if s := fmt.Sprintf(verb, c); strings.Contains(s, canary) {
			t.Errorf("fmt %s leaked the secret: %s", verb, s)
		}
		if s := fmt.Sprintf(verb, &c); strings.Contains(s, canary) {
			t.Errorf("fmt %s on pointer leaked the secret: %s", verb, s)
		}
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(canary)) {
		t.Fatalf("JSON leaked the secret: %s", b)
	}
	if c.Password.Reveal() != canary || c.Email.Reveal() != canary {
		t.Fatal("Reveal must return the wrapped value")
	}
	var empty Secret[string]
	if empty.IsSet() || empty.Reveal() != "" {
		t.Fatal("zero Secret must be unset and reveal the zero value")
	}
}

func TestT041_LogInjectionCannotForgeRecords(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	forged := "ok\n{\"ts\":\"2026-01-01T00:00:00Z\",\"level\":\"ERROR\",\"event\":\"audit.forged\"}\r\n"
	l.Info("user.input", slog.String("note", forged), slog.String("bad_utf8", "a\xff\xfeb"))
	l.Info("x\ny.forged_event", slog.String("ctl", "\x1b[31mred\x00"))
	recs := records(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (injection created extra lines):\n%s", len(recs), buf.String())
	}
	if recs[0]["note"] != forged {
		t.Fatalf("value not preserved verbatim inside one field: %q", recs[0]["note"])
	}
	for _, r := range recs {
		if r["event"] == "audit.forged" {
			t.Fatal("forged record parsed as a real event")
		}
	}
	if s, _ := recs[0]["bad_utf8"].(string); !utf8.ValidString(s) {
		t.Fatalf("invalid UTF-8 was not replaced: %q", s)
	}
}

func TestT041_ValuesAreCapped(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	long := strings.Repeat("é", 5000) // 10,000 bytes of 2-byte runes
	l.Info(strings.Repeat("e", 500), slog.String("long", long), slog.Any("err", errors.New(long)),
		slog.Any("bytes", []byte(long)), slog.Any("list", []string{long}))
	r := records(t, &buf)[0]
	for _, key := range []string{"long", "err", "bytes", "list"} {
		s, _ := r[key].(string)
		if len(s) > MaxValueBytes || !strings.HasSuffix(s, truncMark) || !utf8.ValidString(s) {
			t.Errorf("%s: len %d, suffix ok %v, valid UTF-8 %v", key, len(s), strings.HasSuffix(s, truncMark), utf8.ValidString(s))
		}
	}
	if ev, _ := r[KeyEvent].(string); len(ev) > MaxEventBytes {
		t.Errorf("event not capped: %d bytes", len(ev))
	}
}

func TestMandatoryFields(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{
		Service: "pantherclaw-server", Version: "v0.0.1",
		ContextAttrs: []func(context.Context) []slog.Attr{
			func(context.Context) []slog.Attr { return []slog.Attr{slog.String(KeyTraceID, "trace-1")} },
		},
	})
	ctx := WithAttrs(context.Background(), slog.String(KeyRequestID, "req-1"), slog.String(KeyOrgID, "org-1"))
	l.InfoContext(ctx, "authz.decision", Actor("agent", "a-1"), slog.String(KeyOutcome, "deny"))
	r := records(t, &buf)[0]
	for key, want := range map[string]string{
		KeyEvent: "authz.decision", KeyLevel: "INFO", KeyService: "pantherclaw-server",
		KeyVersion: "v0.0.1", KeyRequestID: "req-1", KeyOrgID: "org-1", KeyTraceID: "trace-1", KeyOutcome: "deny",
	} {
		if r[key] != want {
			t.Errorf("%s = %v, want %q", key, r[key], want)
		}
	}
	ts, _ := r[KeyTime].(string)
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil || !strings.HasSuffix(ts, "Z") || parsed.IsZero() {
		t.Errorf("ts = %q, want UTC RFC 3339 (err %v)", ts, err)
	}
	actor, _ := r[KeyActor].(map[string]any)
	if actor["type"] != "agent" || actor["id"] != "a-1" {
		t.Errorf("actor = %v", r[KeyActor])
	}
	if _, ok := r["msg"]; ok {
		t.Error("raw msg key should be renamed to event")
	}
}

func TestDebugSuppressedAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{})
	l.Debug("debug.event")
	if buf.Len() != 0 {
		t.Fatalf("debug record written at info level: %s", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		if got, ok := ParseLevel(in); !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, ok)
		}
	}
	if _, ok := ParseLevel("verbose"); ok {
		t.Error("ParseLevel accepted an unknown level")
	}
}

func TestNonSensitiveKeysPassThrough(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	l.Info("x.y", slog.String("request_id", "r1"), slog.Int("count", 3), slog.Any("ids", []string{"a", "b"}))
	r := records(t, &buf)[0]
	if r["request_id"] != "r1" || r["count"] != float64(3) || r["ids"] != `["a","b"]` {
		t.Fatalf("unexpected record %v", r)
	}
}
