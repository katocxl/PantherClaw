// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Stable reason codes for authority checks (pipeline steps 3, 4, 7, 8).
const (
	ReasonNoGrant               = "NO_GRANT"
	ReasonGrantRevoked          = "GRANT_REVOKED"
	ReasonGrantExpired          = "GRANT_EXPIRED"
	ReasonGrantNotYetValid      = "GRANT_NOT_YET_VALID"
	ReasonGrantMismatch         = "GRANT_MISMATCH"
	ReasonOperationNotGranted   = "OPERATION_NOT_GRANTED"
	ReasonTargetNotGranted      = "TARGET_NOT_GRANTED"
	ReasonOutsideGuardrail      = "OUTSIDE_GUARDRAIL"
	ReasonGrantLimitExceeded    = "GRANT_LIMIT_EXCEEDED"
	ReasonDestinationNotGranted = "DESTINATION_NOT_GRANTED"
	ReasonOutsideTimeWindow     = "OUTSIDE_TIME_WINDOW"
	ReasonBoundUnchecked        = "BOUND_UNCHECKED"
	ReasonAttestationTooLow     = "ATTESTATION_TOO_LOW"
)

// LevelKind says whether a level is a guardrail or a grant.
type LevelKind string

// Level kinds.
const (
	LevelEnvelope LevelKind = "envelope"
	LevelGrant    LevelKind = "grant"
)

// Level is one layer of authority: an envelope or a grant in the chain.
type Level struct {
	Kind     LevelKind
	ID       ids.UUID
	Revision int
	Label    string
}

func (l Level) String() string { return fmt.Sprintf("%s (revision %d)", l.Label, l.Revision) }

// LevelFinding is a refusal by one level.
type LevelFinding struct {
	Level   Level
	Finding Finding
}

// Reason returns the stable reason code of the finding.
func (lf LevelFinding) Reason() string {
	if lf.Finding.Code != "" {
		return lf.Finding.Code
	}
	if lf.Finding.Outcome == Unknown {
		return ReasonBoundUnchecked
	}
	if lf.Level.Kind == LevelEnvelope {
		return ReasonOutsideGuardrail
	}
	dim := lf.Finding.Dimension
	switch {
	case dim == "operations" || dim == "access":
		return ReasonOperationNotGranted
	case strings.HasPrefix(dim, "targets") || dim == "accounts":
		return ReasonTargetNotGranted
	case strings.HasPrefix(dim, "params."):
		return ReasonGrantLimitExceeded
	case dim == "destinations":
		return ReasonDestinationNotGranted
	case dim == "weekly":
		return ReasonOutsideTimeWindow
	}
	return ReasonGrantLimitExceeded
}

// Detail is the explanation: which level refused, and why.
func (lf LevelFinding) Detail() string {
	return lf.Level.String() + ": " + lf.Finding.Detail
}

// AppliedRequirement is a requirement that applies to an action, with the
// level that set it.
type AppliedRequirement struct {
	Level       Level
	Requirement Requirement
}

// Chain is the authority an action is evaluated against: the applicable
// envelopes and the run's grant with every ancestor, root first.
type Chain struct {
	Envelopes []Envelope
	Grants    []Grant
}

// Leaf returns the run's own grant.
func (c Chain) Leaf() (Grant, bool) {
	if len(c.Grants) == 0 {
		return Grant{}, false
	}
	return c.Grants[len(c.Grants)-1], true
}

// Levels returns every level in evaluation order: envelopes from the org
// down, then grants from the root down.
func (c Chain) Levels() []Level {
	var out []Level
	envs := slices.Clone(c.Envelopes)
	slices.SortStableFunc(envs, func(a, b Envelope) int {
		return slices.Index(scopeOrder, a.Scope.Kind) - slices.Index(scopeOrder, b.Scope.Kind)
	})
	for _, e := range envs {
		out = append(out, Level{Kind: LevelEnvelope, ID: e.ID.UUID(), Revision: e.Revision, Label: fmt.Sprintf("%s guardrail %q", e.Scope, e.Name)})
	}
	for i, g := range c.Grants {
		label := "grant " + g.ID.String()
		if i < len(c.Grants)-1 {
			label = "ancestor " + label
		}
		out = append(out, Level{Kind: LevelGrant, ID: g.ID.UUID(), Revision: g.Revision, Label: label})
	}
	return out
}

type layer struct {
	level        Level
	bounds       Bounds
	requirements []Requirement
}

func (c Chain) layers() []layer {
	levels := c.Levels()
	envs := slices.Clone(c.Envelopes)
	slices.SortStableFunc(envs, func(a, b Envelope) int {
		return slices.Index(scopeOrder, a.Scope.Kind) - slices.Index(scopeOrder, b.Scope.Kind)
	})
	out := make([]layer, 0, len(levels))
	for i, e := range envs {
		out = append(out, layer{levels[i], e.Bounds, e.Requirements})
	}
	for i, g := range c.Grants {
		out = append(out, layer{levels[len(envs)+i], g.Bounds, g.Requirements})
	}
	return out
}

// Validity checks that the run has a grant and that it and every ancestor
// are active and inside their validity windows at now (database clock).
// It returns the first problem as a finding on the grant concerned.
func (c Chain) Validity(now time.Time) (string, *LevelFinding) {
	if len(c.Grants) == 0 {
		return ReasonNoGrant, &LevelFinding{Finding: Finding{Outcome: Denied, Dimension: "grant", Detail: "the run has no grant"}}
	}
	levels := c.Levels()[len(c.Envelopes):]
	for i, g := range c.Grants {
		if code, ok := g.Usable(now); !ok {
			detail := map[string]string{
				ReasonGrantRevoked:     "the grant is revoked",
				ReasonGrantNotYetValid: "the grant is not valid before " + g.NotBefore.UTC().Format(time.RFC3339),
				ReasonGrantExpired:     "the grant expired at " + g.ExpiresAt.UTC().Format(time.RFC3339),
			}[code]
			return code, &LevelFinding{Level: levels[i], Finding: Finding{Outcome: Denied, Dimension: "grant", Detail: detail}}
		}
	}
	return "", nil
}

// Coverage checks every level against what the action touches (step 4) and
// returns every refusal in level order. An empty result means covered.
func (c Chain) Coverage(a Action) []LevelFinding {
	var out []LevelFinding
	for _, l := range c.layers() {
		if f := l.bounds.CheckCoverage(a); f.Outcome != Allowed {
			out = append(out, LevelFinding{Level: l.level, Finding: f})
		}
	}
	return out
}

// Limits checks every level's parameter, destination and time bounds
// (step 7) and returns every refusal in level order.
func (c Chain) Limits(a Action) []LevelFinding {
	var out []LevelFinding
	for _, l := range c.layers() {
		if f := l.bounds.CheckLimits(a); f.Outcome != Allowed {
			out = append(out, LevelFinding{Level: l.level, Finding: f})
		}
	}
	return out
}

// Requirements returns every requirement of every level that applies to
// the action (step 8). A child cannot drop an ancestor's requirement:
// each level's own requirements always apply.
func (c Chain) Requirements(a Action) []AppliedRequirement {
	var out []AppliedRequirement
	for _, l := range c.layers() {
		for _, r := range l.requirements {
			if r.Applies(a) {
				out = append(out, AppliedRequirement{Level: l.level, Requirement: r})
			}
		}
	}
	return out
}

// MinAttestation is the highest minimum attestation level of any level.
func (c Chain) MinAttestation() int {
	m := 0
	for _, e := range c.Envelopes {
		m = max(m, e.MinAttestation)
	}
	for _, g := range c.Grants {
		m = max(m, g.MinAttestation)
	}
	return m
}

// Effective returns the intersection of every level: what the run can use
// now (F046). Decisions never use it directly; they evaluate each level so
// the explanation can name the one that refused.
func (c Chain) Effective() Bounds {
	var out Bounds
	for _, l := range c.layers() {
		out = out.Intersect(l.bounds)
	}
	return out
}

// Version is one level's identity and revision, for the decision basis.
type Version struct {
	Kind     LevelKind `json:"kind"`
	ID       string    `json:"id"`
	Revision int       `json:"revision"`
}

// Versions returns every level's version in evaluation order.
func (c Chain) Versions() []Version {
	var out []Version
	for _, l := range c.Levels() {
		out = append(out, Version{Kind: l.Kind, ID: l.ID.String(), Revision: l.Revision})
	}
	return out
}
