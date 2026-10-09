// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Sessions of the fake browser (see fakeBrowser.Authenticate): "responder"
// holds Emergency Responder and stepped up with responderKey; "reader"
// holds Auditor (containment.read only).
var (
	responderID  = ids.NewV7()
	responderKey = ids.NewV7()
	steppedUpAt  = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
)

// fakeContainment records what the page passed and returns canned results:
// the use case's error when err is set.
type fakeContainment struct {
	mu      sync.Mutex
	state   rapp.State
	err     error
	stepUps []rapp.StepUp
	reasons []string
	ids     []ids.UUID
}

func (f *fakeContainment) seen(su rapp.StepUp, reason string, id ids.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stepUps, f.reasons, f.ids = append(f.stepUps, su), append(f.reasons, reason), append(f.ids, id)
	return f.err
}

func (f *fakeContainment) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stepUps)
}

func (f *fakeContainment) Status(ctx context.Context) (rapp.State, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return rapp.State{}, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return rapp.State{}, err
	}
	return f.state, nil
}

func (f *fakeContainment) Engage(ctx context.Context, su rapp.StepUp, reason string) (rapp.State, error) {
	if _, err := tapp.CallerFrom(ctx); err != nil {
		return rapp.State{}, err
	}
	return rapp.State{Engaged: true, Epoch: 2}, f.seen(su, reason, ids.UUID{})
}

func (f *fakeContainment) ProposeRestore(_ context.Context, su rapp.StepUp, reason string) (rapp.Restore, error) {
	return rapp.Restore{ID: ids.NewV7(), ExpiresAt: steppedUpAt.Add(rapp.RestoreWindow)}, f.seen(su, reason, ids.UUID{})
}

func (f *fakeContainment) ConfirmRestore(_ context.Context, su rapp.StepUp, id ids.UUID) (rapp.State, error) {
	return rapp.State{Epoch: 3}, f.seen(su, "", id)
}

func (f *fakeContainment) CancelRestore(_ context.Context, id ids.UUID) error {
	return f.seen(rapp.StepUp{}, "", id)
}

func newContainmentHandler(t *testing.T) (*fakeContainment, http.Handler) {
	t.Helper()
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeContainment{}
	h.WithContainment(fc)
	mux := http.NewServeMux()
	h.Mount(mux)
	return fc, mux
}

func pageAs(t *testing.T, mux http.Handler, cookie string) result {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, origin+rapp.PagePath, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
	return do(t, mux, r)
}

// postAs is a request that passes the CSRF check, with cookie and body.
func postAs(path, cookie, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, origin+path, strings.NewReader(body))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Origin", origin)
	r.Header.Set(webhttp.CSRFHeader, "1")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
	return r
}

// TestHR113_TheEmergencyStopPageShowsOnlyWhatTheViewerMayDo: the page
// needs containment.read; only a holder of containment.killswitch sees the
// buttons; the proposer of a restore cannot confirm it; untrusted reasons
// are escaped and the only script is the static file.
func TestHR113_TheEmergencyStopPageShowsOnlyWhatTheViewerMayDo(t *testing.T) {
	fc, mux := newContainmentHandler(t)
	if resp := pageAs(t, mux, "good"); resp.StatusCode != http.StatusForbidden || strings.Contains(resp.Body, `id="engage"`) {
		t.Fatalf("no role: %d", resp.StatusCode)
	}
	resp := pageAs(t, mux, "reader")
	if resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "<button") || !strings.Contains(resp.Body, "Emergency Responder role") {
		t.Fatalf("reader: %d %s", resp.StatusCode, resp.Body)
	}
	resp = pageAs(t, mux, "responder")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `id="engage"`) || strings.Contains(resp.Body, "propose-restore") {
		t.Fatalf("responder, not engaged: %d %s", resp.StatusCode, resp.Body)
	}
	if strings.Count(resp.Body, "<script") != 1 || !strings.Contains(resp.Body, `<script src="/static/containment.js"></script>`) {
		t.Fatal("the page must load exactly one script, the static file")
	}

	at := steppedUpAt
	fc.state = rapp.State{Engaged: true, Epoch: 5, EngagedBy: "user:x", EngagedAt: &at, Reason: `<script>alert(1)</script>`}
	resp = pageAs(t, mux, "responder")
	if !strings.Contains(resp.Body, `id="propose-restore"`) || strings.Contains(resp.Body, `id="engage"`) || strings.Contains(resp.Body, "<script>alert") {
		t.Fatalf("responder, engaged: %s", resp.Body)
	}
	fc.state.Pending = &rapp.Restore{ID: ids.NewV7(), ProposedBy: responderID, Reason: `"><img src=x>`, ExpiresAt: at.Add(rapp.RestoreWindow)}
	resp = pageAs(t, mux, "responder")
	if strings.Contains(resp.Body, `id="confirm-restore"`) || !strings.Contains(resp.Body, `id="cancel-restore"`) ||
		!strings.Contains(resp.Body, "You proposed this restore") || strings.Contains(resp.Body, "<img src=x") {
		t.Fatalf("the proposer: %s", resp.Body)
	}
	fc.state.Pending.ProposedBy = ids.NewV7()
	if resp := pageAs(t, mux, "responder"); !strings.Contains(resp.Body, `id="confirm-restore"`) {
		t.Fatalf("a second person: %s", resp.Body)
	}
}

// TestHR113_PageActionsCarryTheSessionsStepUp: each action passes the
// session's own step-up to the use case, needs the CSRF proof, takes a
// strict body and maps refusals to page error codes.
func TestHR113_PageActionsCarryTheSessionsStepUp(t *testing.T) {
	fc, mux := newContainmentHandler(t)
	resp := do(t, mux, postAs(rapp.PagePath+"/kill-switch/engage", "responder", `{"reason":"incident 42"}`))
	if resp.StatusCode != http.StatusOK || fc.calls() != 1 || fc.reasons[0] != "incident 42" ||
		fc.stepUps[0] != (rapp.StepUp{Credential: responderKey, At: steppedUpAt}) {
		t.Fatalf("engage: %d %s %+v", resp.StatusCode, resp.Body, fc.stepUps)
	}
	noCSRF := postAs(rapp.PagePath+"/kill-switch/engage", "responder", `{"reason":"x"}`)
	noCSRF.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, mux, noCSRF); resp.StatusCode != http.StatusForbidden || fc.calls() != 1 {
		t.Fatalf("without the CSRF header: %d, calls %d", resp.StatusCode, fc.calls())
	}
	if resp := do(t, mux, postAs(rapp.PagePath+"/kill-switch/engage", "responder", `{"reason":"x","force":true}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown member: %d", resp.StatusCode)
	}
	if resp := do(t, mux, postAs(rapp.PagePath+"/kill-switch/engage", "nobody", `{"reason":"x"}`)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", resp.StatusCode)
	}

	id := ids.NewV7()
	for _, c := range []struct {
		path   string
		err    error
		status int
		code   string
	}{
		{"/kill-switch/engage", rapp.ErrStepUp, http.StatusForbidden, "step_up_required"},
		{"/kill-switch/engage", td.ErrPermissionDenied(td.PermContainmentKillSwitch), http.StatusForbidden, "forbidden"},
		{"/kill-switch/restore", rapp.ErrRestorePending, http.StatusConflict, "restore_pending"},
		{"/kill-switch/restore/" + id.String() + "/confirm", rapp.ErrSamePerson, http.StatusForbidden, "same_person"},
		{"/kill-switch/restore/" + id.String() + "/confirm", rapp.ErrSameKey, http.StatusForbidden, "same_key"},
		{"/kill-switch/restore/" + id.String() + "/cancel", rapp.ErrRestoreGone, http.StatusConflict, "restore_gone"},
		{"/kill-switch/restore/" + id.String() + "/cancel", rapp.ErrRestoreNotFound, http.StatusNotFound, "not_found"},
	} {
		fc.err = c.err
		resp := do(t, mux, postAs(rapp.PagePath+c.path, "responder", `{"reason":"x"}`))
		if resp.StatusCode != c.status || !strings.Contains(resp.Body, `"error":"`+c.code+`"`) {
			t.Errorf("%s with %v: %d %s", c.path, c.err, resp.StatusCode, resp.Body)
		}
	}
	if fc.ids[len(fc.ids)-1] != id {
		t.Fatal("the proposal id did not reach the use case")
	}
	fc.err = nil
	if resp := do(t, mux, postAs(rapp.PagePath+"/kill-switch/restore/not-an-id/confirm", "responder", `{}`)); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bad id: %d", resp.StatusCode)
	}
}

// TestHR152_SignInMayReturnToTheEmergencyStopPage: a sign-in started from
// the page comes back to it.
func TestHR152_SignInMayReturnToTheEmergencyStopPage(t *testing.T) {
	if rapp.PagePath != authnapp.ContainmentPath || !authnapp.ValidReturnPath(rapp.PagePath) {
		t.Fatal("the emergency-stop page is not a return path")
	}
	_, mux := newContainmentHandler(t)
	r := httptest.NewRequest(http.MethodGet, origin+rapp.PagePath+"?org="+testOrg.String(), nil)
	resp := do(t, mux, r)
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "next=%2Fcontainment") {
		t.Fatalf("no session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}
