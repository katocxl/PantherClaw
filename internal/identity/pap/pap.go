// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pap implements the stateless parts of PAP/1 workload identity
// (PAP-1 §3.4, §4; ADR-0013; G0 M3): workload tokens, request proofs, key
// thumbprints, instance identifiers and nonce slots.
//
// Verification follows the order PAP-1 §4 fixes. VerifyRequest checks the
// token, the proof signature, the key binding and htm/htu/ath/bh, and
// returns a Checked value. Only a Checked value can be consumed: the caller
// then checks that the nonce is current and inserts (jkt, jti) into the
// replay store in one step. So nothing is recorded for a request whose token
// or proof did not verify (HR-090). Every key and algorithm is pinned:
// tokens are EdDSA with a kid from the Authority's workload-token keys;
// proofs are EdDSA with the embedded Ed25519 jwk and nothing else (HR-095).
package pap

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Protocol constants (PAP-1 §3.4, §4).
const (
	// TokenType and ProofType are the JWS typ headers.
	TokenType = "pap-wt+jwt" //nolint:gosec // G101: a JWS typ header value, not a credential
	ProofType = "pap-proof+jwt"
	// TokenAudience is the aud of every workload token.
	TokenAudience = "pantherclaw-gateway"
	// MaxTokenTTL bounds a workload token's lifetime.
	MaxTokenTTL = 10 * time.Minute
	// NonceLifetime bounds how long a server nonce is accepted.
	NonceLifetime = 5 * time.Minute
	// NonceInterval is how often a new nonce is issued per org.
	NonceInterval = time.Minute
	// ReplaySlots is the number of replay-store partitions (00018).
	ReplaySlots = 10
	// MaxProofBytes and MaxTokenBytes cap the compact forms before parsing.
	MaxProofBytes = 8 << 10
	MaxTokenBytes = 8 << 10
	// Leeway tolerates clock skew on iat, nbf and exp.
	Leeway = 60 * time.Second
	// MaxProofAge bounds how old a proof's iat may be; the nonce is the real
	// freshness check, this only stops absurd values.
	MaxProofAge = NonceLifetime + NonceInterval
)

// Code is a PAP-Error code (PAP-1 §12).
type Code string

// Error codes used by workload identity.
const (
	CodeInvalidToken        Code = "invalid_token"
	CodeTokenExpired        Code = "token_expired"
	CodeInvalidProof        Code = "invalid_proof"
	CodeProofReplay         Code = "proof_replay"
	CodeUseNonce            Code = "use_nonce"
	CodeKeyMismatch         Code = "key_mismatch"
	CodeBodyHashMismatch    Code = "body_hash_mismatch"
	CodeInstanceNotAdmitted Code = "instance_not_admitted"
	CodeAttestationLow      Code = "attestation_insufficient"
	CodeRunMismatch         Code = "run_mismatch"
)

// Error is a verification failure with its PAP-Error code. The detail is
// for logs only and never reaches the workload.
type Error struct {
	Code   Code
	detail string
}

func (e *Error) Error() string { return "pap: " + string(e.Code) + ": " + e.detail }

// Is matches errors with the same code.
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Code == e.Code && t.detail == ""
}

// Err returns a comparable sentinel for code, for errors.Is.
func Err(code Code) error { return &Error{Code: code} }

func fail(code Code, format string, a ...any) error {
	return &Error{Code: code, detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the PAP-Error code of err, or invalid_token when err is
// not a PAP error (fail closed).
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInvalidToken
}

// Instance identifies one agent instance: its PAP/1 sub claim is
// pc:org/<org>/agent/<agent>/inst/<instance> (PAP-1 §3.4). The identifier
// carries the org, like every PantherClaw credential (ADR-0016).
type Instance struct {
	Org      ids.OrgID
	Agent    ids.UUID
	Instance ids.UUID
}

var identifierPattern = regexp.MustCompile(`^pc:org/([0-9a-f-]{36})/agent/([0-9a-f-]{36})/inst/([0-9a-f-]{36})$`)

// String formats the identifier.
func (i Instance) String() string {
	return "pc:org/" + i.Org.String() + "/agent/" + i.Agent.String() + "/inst/" + i.Instance.String()
}

// ParseInstance parses an identifier; every id must be a canonical
// lowercase UUID.
func ParseInstance(s string) (Instance, error) {
	m := identifierPattern.FindStringSubmatch(s)
	if m == nil {
		return Instance{}, fail(CodeInvalidToken, "identifier format")
	}
	org, err := ids.Parse[ids.Org](m[1])
	if err != nil || org.String() != m[1] {
		return Instance{}, fail(CodeInvalidToken, "identifier org")
	}
	agent, err1 := ids.ParseUUID(m[2])
	inst, err2 := ids.ParseUUID(m[3])
	if err1 != nil || err2 != nil || agent.String() != m[2] || inst.String() != m[3] || agent.IsZero() || inst.IsZero() {
		return Instance{}, fail(CodeInvalidToken, "identifier ids")
	}
	return Instance{Org: org, Agent: agent, Instance: inst}, nil
}

// NonceMinute is the Unix minute a nonce issued at t belongs to.
func NonceMinute(t time.Time) int64 { return t.Unix() / 60 }

// Slot is the replay-store partition for proofs carrying a nonce issued in
// minute m (dpop_jti.slot = nonce_minute % 10).
func Slot(minute int64) int16 { return int16(minute % ReplaySlots) }

// NonceExpired reports whether a nonce issued in minute m is no longer
// accepted at now: it lives at most NonceLifetime after the end of its
// minute's start, so a proof can carry it for 5 to 6 minutes.
func NonceExpired(minute int64, now time.Time) bool {
	issued := time.Unix(minute*60, 0)
	return !now.Before(issued.Add(NonceInterval + NonceLifetime))
}

var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

// ValidNonce reports whether s has the shape of a server nonce.
func ValidNonce(s string) bool { return noncePattern.MatchString(s) }
