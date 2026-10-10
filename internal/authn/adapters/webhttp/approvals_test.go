// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// knownRequest is the one request fakeApprovals shows.
var knownRequest = ids.NewV7()

// fakeApprovals shows knownRequest, with agent text and evidence that try
// to inject markup, and an inbox holding it (or nothing, when empty).
type fakeApprovals struct {
	empty bool
}

func (f *fakeApprovals) Inbox(ctx context.Context) (apapp.Inbox, error) {
	if _, err := tapp.CallerFrom(ctx); err != nil {
		return apapp.Inbox{}, err
	}
	in := apapp.Inbox{Scopes: []td.Binding{{Role: td.RoleApprover, Scope: td.Scope{Type: td.ScopeOrg, ID: testOrg.UUID()}}}}
	if !f.empty {
		in.Waiting = []apapp.Summary{{
			ID: knownRequest, Title: `Refund <b>40.00 USD</b>`, Operation: "payments.refund.create", State: "PENDING", Priority: 2,
		}}
	}
	return in, nil
}

func (f *fakeApprovals) View(ctx context.Context, id ids.UUID) (apapp.View, error) {
	if _, err := tapp.CallerFrom(ctx); err != nil {
		return apapp.View{}, err
	}
	if id != knownRequest {
		return apapp.View{}, apapp.ErrNotFound
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	return apapp.View{
		Request: apapp.Request{ID: id, DeadlineAt: now.Add(time.Hour)},
		Display: apdomain.Display{
			V: 1, Kind: "ACTION", Title: "Refund 40.00 USD",
			Consequence: apdomain.Consequence{
				Operation: "payments.refund.create", Target: actionir.Target{Type: "charge", ID: "ch_123"}, Reversibility: "irreversible",
			},
			Fields: []apdomain.Field{{Name: "amount", Value: "40.00 USD"}},
			Facts: []apdomain.FactLine{{
				Name: "charge.amount", Subject: "ch_123", Value: "40.00 USD", Provider: "stripe",
				ObservedAt: now.Add(-90 * time.Second).Format(time.RFC3339),
			}},
			Deciders: []apdomain.DeciderRule{{Kind: "approval", Role: "approver", Count: 1}},
			Untrusted: apdomain.UntrustedBlock{Label: apdomain.UntrustedLabel, Items: []apdomain.Untrusted{
				{Source: "task_label", Text: `<script>alert(1)</script>`},
				{Source: "param:memo", Text: "p" + string(rune(0x0430)) + "ypal", MixedScript: true},
			}},
		},
		State: "PENDING", Now: now, MayRespond: true, MayApprove: true,
		Evidence: []apapp.EvidenceLine{{Author: "instance:x", Note: apdomain.Untrusted{Source: "evidence", Text: `"><img src=x onerror=alert(1)>`}, At: now}},
	}, nil
}

func newApprovalsHandler(t *testing.T, fa *fakeApprovals) http.Handler {
	t.Helper()
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.WithApprovals(fa)
	mux := http.NewServeMux()
	h.Mount(mux)
	return mux
}

func getAs(t *testing.T, mux http.Handler, path, cookie string) result {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, origin+path, nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
	}
	return do(t, mux, r)
}

// TestHR034_TheApprovalPageShowsTheStoredDisplayAndMarksUntrustedText: the
// page shows the consequence, fields and facts (with their age) of the
// stored display, puts agent text under the fixed label, escapes it, flags
// mixed scripts, and carries the page policy.
func TestHR034_TheApprovalPageShowsTheStoredDisplayAndMarksUntrustedText(t *testing.T) {
	mux := newApprovalsHandler(t, &fakeApprovals{})
	resp := getAs(t, mux, authnapp.ApprovalsPath+"/"+knownRequest.String(), "good")
	body := resp.Body
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Security-Policy") != webhttp.PageCSP ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	for _, want := range []string{
		"Refund 40.00 USD", "payments.refund.create", "ch_123", "irreversible", "40.00 USD", "stripe", "<td>1m</td>",
		apdomain.UntrustedLabel, "&lt;script&gt;alert(1)&lt;/script&gt;", "mixes writing systems", "You can approve",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
		t.Fatal("untrusted text is not escaped")
	}
	if i, j := strings.Index(body, "What will happen"), strings.Index(body, apdomain.UntrustedLabel); i < 0 || j < i {
		t.Fatal("the consequence must come first, before the untrusted block")
	}
}

// TestT037_AnUnknownOrHiddenRequestIsNotFound: an id the person may not see,
// an unknown id and a malformed id all get the same "not found".
func TestT037_AnUnknownOrHiddenRequestIsNotFound(t *testing.T) {
	mux := newApprovalsHandler(t, &fakeApprovals{})
	for _, path := range []string{authnapp.ApprovalsPath + "/" + ids.NewV7().String(), authnapp.ApprovalsPath + "/not-an-id"} {
		resp := getAs(t, mux, path, "good")
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(resp.Body, "does not exist, or you cannot see it") {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}

// TestF626_TheListSaysWhatWasChecked: the list links the waiting requests
// and, empty or not, names the scopes it checked.
func TestF626_TheListSaysWhatWasChecked(t *testing.T) {
	resp := getAs(t, newApprovalsHandler(t, &fakeApprovals{}), authnapp.ApprovalsPath, "good")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `href="/approvals/`+knownRequest.String()+`"`) ||
		!strings.Contains(resp.Body, "Refund &lt;b&gt;40.00 USD&lt;/b&gt;") || !strings.Contains(resp.Body, "What was checked") {
		t.Fatalf("list: %d %s", resp.StatusCode, resp.Body)
	}
	resp = getAs(t, newApprovalsHandler(t, &fakeApprovals{empty: true}), authnapp.ApprovalsPath, "good")
	if !strings.Contains(resp.Body, "Nothing is waiting for your decision") || !strings.Contains(resp.Body, "<code>approver</code> at ORG") {
		t.Fatalf("empty list: %s", resp.Body)
	}
}

// TestHR152_SignInReturnsToTheApprovalPage: without a session, a link that
// names the org goes to sign-in with the page as next.
func TestHR152_SignInReturnsToTheApprovalPage(t *testing.T) {
	mux := newApprovalsHandler(t, &fakeApprovals{})
	path := authnapp.ApprovalsPath + "/" + knownRequest.String()
	resp := getAs(t, mux, path+"?org="+testOrg.String(), "")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "next=%2Fapprovals%2F"+knownRequest.String()) {
		t.Fatalf("%d %s", resp.StatusCode, loc)
	}
	if !authnapp.ValidReturnPath(path) {
		t.Fatal("the approval page must be a valid return path")
	}
}
