// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeKeys returns canned results: the ceremony id "recent" asks for recent
// authentication, a removal of a nil id fails with not-found.
type fakeKeys struct{}

var testCeremony = ids.NewV7()

func (fakeKeys) BeginRegistration(context.Context, authnapp.BrowserSession) (authnapp.Ceremony, error) {
	return authnapp.Ceremony{}, authnapp.ErrRecentAuthRequired
}

func (fakeKeys) FinishRegistration(_ context.Context, _ authnapp.BrowserSession, c ids.UUID, name string, resp []byte) (authnapp.CredentialInfo, error) {
	if c != testCeremony || !jsontext.Value(resp).IsValid() {
		return authnapp.CredentialInfo{}, authnapp.ErrCeremonyInvalid
	}
	return authnapp.CredentialInfo{ID: ids.NewV7(), Name: name}, nil
}

func (fakeKeys) BeginStepUp(context.Context, authnapp.BrowserSession) (authnapp.Ceremony, error) {
	return authnapp.Ceremony{ID: testCeremony, Options: []byte(`{"publicKey":{"challenge":"AAAA"}}`)}, nil
}

func (fakeKeys) FinishStepUp(_ context.Context, _ authnapp.BrowserSession, c ids.UUID, _ []byte) (authnapp.StepUp, error) {
	if c != testCeremony {
		return authnapp.StepUp{}, authnapp.ErrCredentialSuspended
	}
	return authnapp.StepUp{Rotated: "stepped-up"}, nil
}

func (fakeKeys) ListCredentials(context.Context, authnapp.BrowserSession) ([]authnapp.CredentialInfo, error) {
	return []authnapp.CredentialInfo{{ID: ids.NewV7(), Name: `<b>key</b>`, State: "ACTIVE"}}, nil
}

func (fakeKeys) RenameCredential(context.Context, authnapp.BrowserSession, ids.UUID, string) error {
	return authnapp.ErrBadCredentialName
}

func (fakeKeys) RemoveCredential(context.Context, authnapp.BrowserSession, ids.UUID) error {
	return authnapp.ErrCredentialNotFound
}

func postJSON(path, body string) *http.Request {
	r := post(path)
	r.Body = httpBody(body)
	return r
}

func TestHR155_KeyRoutesExplainWhatIsMissing(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	resp := do(t, mux, post(authnapp.AccountPath+"/keys/registration-options"))
	var body map[string]string
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil || resp.StatusCode != http.StatusForbidden || body["error"] != "recent_auth_required" {
		t.Fatalf("registration options: %d %s", resp.StatusCode, resp.Body)
	}
	u, err := url.Parse(body["sign_in"])
	if err != nil || u.Path != authnapp.LoginPath || u.Query().Get("recent") != "1" || u.Query().Get("org") != testOrg.String() ||
		u.Query().Get("next") != authnapp.AccountPath {
		t.Fatalf("sign-in link %q", body["sign_in"])
	}
	for _, tc := range []struct {
		path, body string
		status     int
		code       string
	}{
		{"/keys", `{"ceremony":"` + testCeremony.String() + `","name":"k","response":{"id":"x"},"extra":1}`, 400, "bad_request"},
		{"/keys", `{"ceremony":"` + testCeremony.String() + `","name":"k","name":"k2","response":{}}`, 400, "bad_request"},
		{"/keys", `{"ceremony":"not-a-uuid","name":"k","response":{}}`, 400, "bad_request"},
		{"/keys", `{"ceremony":"` + ids.NewV7().String() + `","name":"k","response":{}}`, 400, "ceremony_invalid"},
		{"/keys/" + ids.NewV7().String() + "/rename", `{"name":"x"}`, 400, "bad_name"},
		{"/keys/" + ids.NewV7().String() + "/remove", `{}`, 404, "not_found"},
		{"/step-up", `{"ceremony":"` + ids.NewV7().String() + `","response":{}}`, 403, "key_suspended"},
	} {
		resp := do(t, mux, postJSON(authnapp.AccountPath+tc.path, tc.body))
		if resp.StatusCode != tc.status || !strings.Contains(resp.Body, `"`+tc.code+`"`) {
			t.Errorf("POST %s %s: %d %s, want %d %s", tc.path, tc.body, resp.StatusCode, resp.Body, tc.status, tc.code)
		}
	}
	resp = do(t, mux, postJSON(authnapp.AccountPath+"/keys", `{"ceremony":"`+testCeremony.String()+`","name":"Desk","response":{"id":"x"}}`))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"Desk"`) {
		t.Fatalf("add key: %d %s", resp.StatusCode, resp.Body)
	}
}

func TestHR156_StepUpReplacesTheSessionCookie(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	resp := do(t, mux, post(authnapp.AccountPath+"/step-up-options"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"ceremony":"`+testCeremony.String()+`"`) ||
		!strings.Contains(resp.Body, `"options":{"publicKey"`) {
		t.Fatalf("step-up options: %d %s", resp.StatusCode, resp.Body)
	}
	resp = do(t, mux, postJSON(authnapp.AccountPath+"/step-up", `{"ceremony":"`+testCeremony.String()+`","response":{"id":"x"}}`))
	cs := resp.Cookies()
	if resp.StatusCode != http.StatusOK || len(cs) != 1 || cs[0].Name != "__Host-pc_session" || cs[0].Value != "stepped-up" ||
		cs[0].SameSite != http.SameSiteStrictMode || !cs[0].HttpOnly || !cs[0].Secure {
		t.Fatalf("step-up: %d %+v", resp.StatusCode, cs)
	}
}

func TestHR151_KeyNamesAreEscapedOnTheAccountPage(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	r := httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	resp := do(t, mux, r)
	if resp.StatusCode != http.StatusOK || strings.Contains(resp.Body, "<b>key</b>") || !strings.Contains(resp.Body, "&lt;b&gt;key&lt;/b&gt;") {
		t.Fatalf("account page: %d", resp.StatusCode)
	}
}

func httpBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
