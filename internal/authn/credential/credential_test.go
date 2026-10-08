// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package credential_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestRoundTrip(t *testing.T) {
	org := ids.New[ids.Org]()
	pattern := regexp.MustCompile(`^pck_live_[0-9a-f]{32}_[0-9A-Za-z]{43}$`)
	for _, tc := range []struct {
		kind credential.Kind
		env  credential.Env
	}{
		{credential.APIKey, credential.EnvLive},
		{credential.APIKey, credential.EnvDev},
		{credential.Invitation, ""},
		{credential.DeviceCode, ""},
		{credential.RefreshToken, ""},
		{credential.OAuthState, ""},
	} {
		tok, err := credential.New(tc.kind, tc.env, org)
		if err != nil {
			t.Fatal(err)
		}
		if tc.kind == credential.APIKey && tc.env == credential.EnvLive && !pattern.MatchString(tok.Reveal()) {
			t.Fatalf("API key format: %q", tok.Reveal())
		}
		got, err := credential.Parse(tc.kind, tok.Reveal())
		if err != nil {
			t.Fatalf("Parse(%s): %v", tc.kind, err)
		}
		if got.Org() != org || got.Env() != tc.env || got.Kind() != tc.kind || !bytes.Equal(got.Hash(), tok.Hash()) {
			t.Fatalf("round trip mismatch for %s", tc.kind)
		}
		if len(tok.Hash()) != 32 || len(tok.Reveal()) > credential.MaxLen {
			t.Fatal("hash or length out of bounds")
		}
	}
}

func TestSecretsAreUniqueAndNeverPrinted(t *testing.T) {
	org := ids.New[ids.Org]()
	seen := map[string]bool{}
	for range 200 {
		tok, err := credential.New(credential.RefreshToken, "", org)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.Reveal()] {
			t.Fatal("duplicate secret")
		}
		seen[tok.Reveal()] = true
		secret := tok.Reveal()[len(tok.Reveal())-43:]
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "token", tok)
		for _, s := range []string{tok.String(), fmt.Sprint(tok), fmt.Sprintf("%v %+v", tok, tok), buf.String()} {
			if strings.Contains(s, secret[:20]) {
				t.Fatalf("secret leaked in %q", s)
			}
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	org := ids.New[ids.Org]()
	key, _ := credential.New(credential.APIKey, credential.EnvTest, org)
	inv, _ := credential.New(credential.Invitation, "", org)
	raw := key.Reveal()
	cases := map[string]string{
		"empty":          "",
		"other kind":     inv.Reveal(),
		"unknown env":    strings.Replace(raw, "_test_", "_prod_", 1),
		"uppercase org":  raw[:9] + strings.ToUpper(raw[9:41]) + raw[41:],
		"short secret":   raw[:len(raw)-1],
		"long secret":    raw + "A",
		"bad secret":     raw[:len(raw)-1] + "-",
		"nil org":        "pck_test_" + strings.Repeat("0", 32) + raw[41:],
		"v4 org":         "pck_test_" + "4b0c8a0c3f2b4c1a9d3e2f1a0b9c8d7e" + raw[41:],
		"no separator":   strings.Replace(raw, "_", "", 3),
		"oversized":      raw + strings.Repeat("A", 200),
		"unicode digits": raw[:len(raw)-1] + "٣",
	}
	for name, s := range cases {
		if _, err := credential.Parse(credential.APIKey, s); !errors.Is(err, credential.ErrMalformed) {
			t.Errorf("%s: Parse(%q) = %v, want ErrMalformed", name, s, err)
		}
	}
	if _, err := credential.Parse(credential.Invitation, raw); err == nil {
		t.Error("API key parsed as an invitation")
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	org := ids.New[ids.Org]()
	for _, tc := range []struct {
		kind credential.Kind
		env  credential.Env
		org  ids.OrgID
	}{
		{credential.APIKey, "", org},
		{credential.APIKey, "prod", org},
		{credential.Invitation, credential.EnvLive, org},
		{"pcx", "", org},
		{credential.Invitation, "", ids.OrgID{}},
	} {
		if _, err := credential.New(tc.kind, tc.env, tc.org); err == nil {
			t.Errorf("New(%q, %q) accepted", tc.kind, tc.env)
		}
	}
}

type account struct{}

func (account) KindName() string { return "service_account" }

func TestClientID(t *testing.T) {
	org := ids.New[ids.Org]()
	acct := ids.New[account]()
	id := credential.FormatClientID(org, acct)
	if !regexp.MustCompile(`^pcsa_[0-9a-f]{32}_[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("client id %q", id)
	}
	gotOrg, gotAcct, err := credential.ParseClientID[account](id)
	if err != nil || gotOrg != org || gotAcct != acct {
		t.Fatalf("ParseClientID = %v %v %v", gotOrg, gotAcct, err)
	}
	for _, bad := range []string{"", "pcsa_", id + "0", id[:len(id)-1], strings.Replace(id, "_", "-", 2), "pcsb" + id[4:]} {
		if _, _, err := credential.ParseClientID[account](bad); err == nil {
			t.Errorf("ParseClientID(%q) accepted", bad)
		}
	}
}

func TestUserCodes(t *testing.T) {
	alphabet := regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{8}$`) // the device_codes CHECK
	counts := map[rune]int{}
	for range 2000 {
		c, err := credential.NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if !alphabet.MatchString(c) {
			t.Fatalf("user code %q", c)
		}
		for _, r := range c {
			counts[r]++
		}
		got, ok := credential.NormalizeUserCode(strings.ToLower(credential.FormatUserCode(c)))
		if !ok || got != c {
			t.Fatalf("normalize(%q) = %q, %v", credential.FormatUserCode(c), got, ok)
		}
	}
	// 16,000 letters over 20 symbols: each ≈ 800; a broken sampler shows.
	for r, n := range counts {
		if n < 600 || n > 1000 {
			t.Errorf("letter %c drawn %d times", r, n)
		}
	}
	for _, bad := range []string{"", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF_GHJK", "ВCDF-GHJK"} {
		if _, ok := credential.NormalizeUserCode(bad); ok {
			t.Errorf("NormalizeUserCode(%q) accepted", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	org := ids.New[ids.Org]()
	tok, _ := credential.New(credential.APIKey, credential.EnvLive, org)
	f.Add(tok.Reveal())
	f.Add("pck_live__")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := credential.Parse(credential.APIKey, s)
		if err != nil {
			return
		}
		if got.Reveal() != s || got.Org().IsZero() || !got.Env().Valid() {
			t.Fatalf("accepted %q with inconsistent fields", s)
		}
	})
}
