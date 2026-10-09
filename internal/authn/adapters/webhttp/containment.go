// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Containment is the kill-switch use-case set (response/app.Service). The
// emergency-stop page is the only place the kill switch is engaged or
// restored (G0 M6 decision 2, HR-113).
type Containment interface {
	Status(ctx context.Context) (rapp.State, error)
	Engage(ctx context.Context, su rapp.StepUp, reason string) (rapp.State, error)
	ProposeRestore(ctx context.Context, su rapp.StepUp, reason string) (rapp.Restore, error)
	ConfirmRestore(ctx context.Context, su rapp.StepUp, id ids.UUID) (rapp.State, error)
	CancelRestore(ctx context.Context, id ids.UUID) error
}

// WithContainment adds the emergency-stop page; call it before Mount.
func (h *Handler) WithContainment(c Containment) *Handler {
	h.containment = c
	return h
}

func (h *Handler) mountContainment(m *http.ServeMux) {
	if h.containment == nil {
		return
	}
	h.withSession(m, http.MethodGet, rapp.PagePath, h.containmentPage)
	h.withSession(m, http.MethodPost, rapp.PagePath+"/kill-switch/engage", h.engage)
	h.withSession(m, http.MethodPost, rapp.PagePath+"/kill-switch/restore", h.proposeRestore)
	h.withSession(m, http.MethodPost, rapp.PagePath+"/kill-switch/restore/{id}/confirm", h.confirmRestore)
	h.withSession(m, http.MethodPost, rapp.PagePath+"/kill-switch/restore/{id}/cancel", h.cancelRestore)
}

// containmentPage is the data of containment.html.
type containmentPage struct {
	page
	KillSwitch rapp.State
	// CanAct: the person holds containment.killswitch. IsProposer: they
	// proposed the pending restore, so they cannot confirm it.
	CanAct, IsProposer bool
}

// callerContext carries the session's caller to the use cases.
func callerContext(r *http.Request, s authnapp.BrowserSession) context.Context {
	return tenancy.WithCaller(r.Context(), s.Caller)
}

func stepUpOf(s authnapp.BrowserSession) rapp.StepUp {
	return rapp.StepUp{Credential: s.StepUpCredential, At: s.StepUpAt}
}

func (h *Handler) containmentPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r) // a link for another org: sign in there
		return
	}
	st, err := h.containment.Status(callerContext(r, s))
	var pe *pcerr.Error
	switch {
	case errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied:
		h.render(w, http.StatusForbidden, "error.html", page{
			Title: "Emergency stop", Message: "You cannot see the kill switch of this organization. Ask an administrator for a role that can.",
		})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	p := containmentPage{
		page:       page{Title: "Emergency stop", Session: s},
		KillSwitch: st,
		CanAct:     s.Human() && s.Can(td.PermContainmentKillSwitch, td.OrgPath(s.Org)),
		IsProposer: st.Pending != nil && st.Pending.ProposedBy == s.Principal.ID,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := pages.ExecuteTemplate(w, "containment.html", p); err != nil {
		h.log.Error("web.render", slog.String("template", "containment.html"), pclog.Err(err))
	}
}

// reasonRequest is the body of engage and propose.
type reasonRequest struct {
	Reason string `json:"reason"`
}

// readReason decodes a strict JSON body (an empty body means no reason).
func readReason(r *http.Request) (string, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	var req reasonRequest
	if err := json.Unmarshal(b, &req, json.RejectUnknownMembers(true)); err != nil {
		return "", err
	}
	return req.Reason, nil
}

// containmentErrors maps use-case errors to the page's error codes.
var containmentErrors = []struct {
	err    error
	status int
	code   string
}{
	{rapp.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{rapp.ErrReason, http.StatusBadRequest, "reason_required"},
	{rapp.ErrAlreadyEngaged, http.StatusConflict, "already_engaged"},
	{rapp.ErrNotEngaged, http.StatusConflict, "not_engaged"},
	{rapp.ErrRestorePending, http.StatusConflict, "restore_pending"},
	{rapp.ErrRestoreGone, http.StatusConflict, "restore_gone"},
	{rapp.ErrRestoreNotFound, http.StatusNotFound, "not_found"},
	{rapp.ErrSamePerson, http.StatusForbidden, "same_person"},
	{rapp.ErrSameKey, http.StatusForbidden, "same_key"},
}

func (h *Handler) containmentError(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range containmentErrors {
		if errors.Is(err, e.err) {
			h.writeJSON(w, e.status, map[string]string{"error": e.code})
			return
		}
	}
	var pe *pcerr.Error
	if errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.log.ErrorContext(r.Context(), "web.containment", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (h *Handler) engage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	reason, err := readReason(r)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	st, err := h.containment.Engage(callerContext(r, s), stepUpOf(s), reason)
	if err != nil {
		h.containmentError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"engaged": true, "epoch": st.Epoch})
}

func (h *Handler) proposeRestore(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	reason, err := readReason(r)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	p, err := h.containment.ProposeRestore(callerContext(r, s), stepUpOf(s), reason)
	if err != nil {
		h.containmentError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"id": p.ID.String(), "expires": p.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")})
}

func (h *Handler) confirmRestore(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	st, err := h.containment.ConfirmRestore(callerContext(r, s), stepUpOf(s), id)
	if err != nil {
		h.containmentError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"engaged": st.Engaged, "epoch": st.Epoch})
}

func (h *Handler) cancelRestore(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	if err := h.containment.CancelRestore(callerContext(r, s), id); err != nil {
		h.containmentError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"canceled": true})
}
