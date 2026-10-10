// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// BindingVersion is the version field "v" of every binding (PAP-1 §8,
// design decision 13).
const BindingVersion = 1

// RestoreSubject is the subject a restoration binding names.
const RestoreSubject = "agent.restore"

var jktPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Binding is a computed binding: the canonical JSON it hashes (stored with
// the request) and its SHA-256, which is also the WebAuthn challenge
// (HR-033, design decision 12).
type Binding struct {
	Input []byte
	Hash  [32]byte
}

// String returns the hash as base64url without padding.
func (b Binding) String() string { return B64(b.Hash[:]) }

// B64 encodes bytes as base64url without padding, as PAP-1 does.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// hash32 accepts a SHA-256 as 64 hex digits, with or without a "sha256:"
// prefix, or as 43 base64url characters, and returns it as base64url.
func hash32(name, s string) (string, error) {
	h := strings.TrimPrefix(s, "sha256:")
	if b, err := hex.DecodeString(h); err == nil && len(b) == 32 {
		return B64(b), nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return B64(b), nil
	}
	return "", fmt.Errorf("approvals: %s is not a SHA-256", name)
}

// GrantRef names the run's grant and its revision; the whole chain is in
// the decision basis.
type GrantRef struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}

// ActionBinding is the binding input of a held action (PAP-1 §8, HR-030):
// the action as requested and as it will run, the decision basis, the
// facts, the grant revision, the definition, the run, the instance and its
// key, who must approve, the deadline and the rendered display.
type ActionBinding struct {
	V                    int                `json:"v"`
	ActionHash           string             `json:"action_hash"`
	EffectiveActionHash  string             `json:"effective_action_hash"`
	DecisionBasisDigest  string             `json:"decision_basis_digest"`
	MaterialFactsDigest  string             `json:"material_facts_digest"`
	Grant                GrantRef           `json:"grant"`
	DefinitionDigest     string             `json:"definition_digest"`
	RunID                string             `json:"run_id"`
	AgentInstance        string             `json:"agent_instance"`
	JKT                  string             `json:"jkt"`
	ApproverRequirements []BoundRequirement `json:"approver_requirements"`
	ExpiresAt            string             `json:"expires_at"`
	DisplayHash          string             `json:"display_hash"`
}

// ActionParts are the values an action binding is built from. Hashes may
// be hex, "sha256:"-prefixed hex or base64url; the binding writes them as
// base64url. ExpiresAt is written as RFC 3339 UTC in whole seconds.
type ActionParts struct {
	ActionHash          string
	EffectiveActionHash string
	BasisDigest         string
	FactsDigest         string
	DefinitionDigest    string
	GrantID             ids.UUID
	GrantRevision       int
	RunID               ids.UUID
	Instance            ids.UUID
	JKT                 string
	Requirements        []Requirement
	ExpiresAt           time.Time
	DisplayHash         [32]byte
}

// Binding computes the action binding.
func (p ActionParts) Binding() (Binding, error) {
	b := ActionBinding{
		V: BindingVersion, Grant: GrantRef{ID: p.GrantID.String(), Revision: p.GrantRevision},
		RunID: p.RunID.String(), AgentInstance: p.Instance.String(), JKT: p.JKT,
		ApproverRequirements: Bound(p.Requirements), DisplayHash: B64(p.DisplayHash[:]),
	}
	var err error
	for _, f := range []struct {
		name, in string
		out      *string
	}{
		{"action_hash", p.ActionHash, &b.ActionHash},
		{"effective_action_hash", p.EffectiveActionHash, &b.EffectiveActionHash},
		{"decision_basis_digest", p.BasisDigest, &b.DecisionBasisDigest},
		{"material_facts_digest", p.FactsDigest, &b.MaterialFactsDigest},
		{"definition_digest", p.DefinitionDigest, &b.DefinitionDigest},
	} {
		if *f.out, err = hash32(f.name, f.in); err != nil {
			return Binding{}, err
		}
	}
	switch {
	case p.GrantID.IsZero() || p.GrantRevision < 1:
		return Binding{}, errors.New("approvals: the binding needs the grant and its revision")
	case p.RunID.IsZero() || p.Instance.IsZero():
		return Binding{}, errors.New("approvals: the binding needs the run and the instance")
	case !jktPattern.MatchString(p.JKT):
		return Binding{}, errors.New("approvals: the binding needs the workload key thumbprint")
	}
	if b.ExpiresAt, err = expires(p.ExpiresAt); err != nil {
		return Binding{}, err
	}
	if len(b.ApproverRequirements) == 0 {
		return Binding{}, errors.New("approvals: the binding needs its requirements")
	}
	return canonical(b)
}

// RestorationBinding is the binding input of a restoration (decision 11):
// the agent, the change it was at when the request was made, the state it
// returns to, who asked and why, who must approve, the deadline and the
// display.
type RestorationBinding struct {
	V                    int                `json:"v"`
	Subject              string             `json:"subject"`
	AgentID              string             `json:"agent_id"`
	AgentChangeSeq       int64              `json:"agent_change_seq"`
	RequestedState       string             `json:"requested_state"`
	RequestedBy          string             `json:"requested_by"`
	ReasonHash           string             `json:"reason_hash"`
	ApproverRequirements []BoundRequirement `json:"approver_requirements"`
	ExpiresAt            string             `json:"expires_at"`
	DisplayHash          string             `json:"display_hash"`
}

// RestorationParts are the values a restoration binding is built from.
// ChangeSeq counts the agent's recorded changes, so any later change to the
// agent gives a different binding.
type RestorationParts struct {
	AgentID        ids.UUID
	ChangeSeq      int64
	RequestedState string
	RequestedBy    ids.UUID
	Reason         string
	Requirements   []Requirement
	ExpiresAt      time.Time
	DisplayHash    [32]byte
}

// Binding computes the restoration binding.
func (p RestorationParts) Binding() (Binding, error) {
	if p.AgentID.IsZero() || p.RequestedBy.IsZero() || p.RequestedState == "" || p.ChangeSeq < 0 || len(p.Requirements) == 0 {
		return Binding{}, errors.New("approvals: an incomplete restoration binding")
	}
	reason := sha256.Sum256([]byte(p.Reason))
	b := RestorationBinding{
		V: BindingVersion, Subject: RestoreSubject, AgentID: p.AgentID.String(), AgentChangeSeq: p.ChangeSeq,
		RequestedState: p.RequestedState, RequestedBy: "user:" + p.RequestedBy.String(), ReasonHash: B64(reason[:]),
		ApproverRequirements: Bound(p.Requirements), DisplayHash: B64(p.DisplayHash[:]),
	}
	var err error
	if b.ExpiresAt, err = expires(p.ExpiresAt); err != nil {
		return Binding{}, err
	}
	return canonical(b)
}

func expires(t time.Time) (string, error) {
	if t.IsZero() || !t.Equal(t.Truncate(time.Second)) {
		return "", errors.New("approvals: the binding's expiry is a time in whole seconds")
	}
	return t.UTC().Format(time.RFC3339), nil
}

// canonical returns SHA-256(JCS(v)) and the JCS bytes (RFC 8785).
func canonical(v any) (Binding, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Binding{}, err
	}
	val := jsontext.Value(raw)
	if err := val.Canonicalize(); err != nil {
		return Binding{}, err
	}
	return Binding{Input: slices.Clone([]byte(val)), Hash: sha256.Sum256(val)}, nil
}

// BatchChallenge is the WebAuthn challenge of a batch approval (HR-175):
// SHA-256(JCS({v: 1, batch: [sorted bindings]})), so one assertion covers
// exactly those requests.
func BatchChallenge(bindings [][32]byte) (Binding, error) {
	if len(bindings) == 0 {
		return Binding{}, errors.New("approvals: an empty batch")
	}
	out := make([]string, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, B64(b[:]))
	}
	slices.Sort(out)
	if len(slices.Compact(slices.Clone(out))) != len(out) {
		return Binding{}, errors.New("approvals: a batch names one request twice")
	}
	return canonical(struct {
		V     int      `json:"v"`
		Batch []string `json:"batch"`
	}{BindingVersion, out})
}

// Target is the target of an action as the variant key sees it.
type Target struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Account string `json:"account,omitzero"`
}

// VariantKey groups requests for the same grant, operation and target
// (HR-037): SHA-256(JCS({grant, operation, target})).
func VariantKey(grant ids.UUID, operation string, t Target) ([32]byte, error) {
	if grant.IsZero() || operation == "" || t.Type == "" || t.ID == "" {
		return [32]byte{}, errors.New("approvals: a variant key needs the grant, operation and target")
	}
	b, err := canonical(struct {
		Grant     string `json:"grant"`
		Operation string `json:"operation"`
		Target    Target `json:"target"`
	}{grant.String(), operation, t})
	return b.Hash, err
}
