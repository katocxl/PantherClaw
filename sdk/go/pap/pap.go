// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package pap contains wire-level constants of the PantherClaw Authority
// Protocol, version 1 (PAP/1). See docs/protocol/PAP-1.md in the PantherClaw
// repository for the normative specification.
package pap

// Version is the PAP major version implemented by this package.
const Version = 1

// HTTP header names defined by PAP/1.
const (
	// HeaderProof carries the per-request proof-of-possession JWS (PAP/1 §4).
	HeaderProof = "PAP-Proof"
	// HeaderNonce carries a server-issued proof nonce (PAP/1 §4).
	HeaderNonce = "PAP-Nonce"
	// HeaderError carries a machine-readable PAP error code (PAP/1 §12).
	HeaderError = "PAP-Error"
	// HeaderAction carries a target-enforced action token (PAP/1 §10).
	HeaderAction = "PAP-Action"
	// AuthScheme is the HTTP Authorization scheme for workload tokens (PAP/1 §4).
	AuthScheme = "PAP"
)

// JOSE "typ" header values defined by PAP/1.
const (
	TypeWorkloadToken   = "pap-wt+jwt" //nolint:gosec // G101 false positive: JOSE "typ" value, not a credential
	TypeProof           = "pap-proof+jwt"
	TypePermit          = "pap-permit+jwt"
	TypeDecisionReceipt = "pap-decision+jwt"
)

// ErrorCode is a PAP/1 error code (PAP/1 §12).
type ErrorCode string

// PAP/1 error codes.
const (
	ErrInvalidToken            ErrorCode = "invalid_token"
	ErrTokenExpired            ErrorCode = "token_expired"
	ErrInvalidProof            ErrorCode = "invalid_proof"
	ErrProofReplay             ErrorCode = "proof_replay"
	ErrUseNonce                ErrorCode = "use_nonce"
	ErrKeyMismatch             ErrorCode = "key_mismatch"
	ErrBodyHashMismatch        ErrorCode = "body_hash_mismatch"
	ErrInstanceNotAdmitted     ErrorCode = "instance_not_admitted"
	ErrAttestationInsufficient ErrorCode = "attestation_insufficient"
	ErrRunMismatch             ErrorCode = "run_mismatch"
	ErrActionTampered          ErrorCode = "action_tampered"
	ErrUnknownRoute            ErrorCode = "unknown_route"
	ErrDefinitionInactive      ErrorCode = "definition_inactive"
	ErrAmbiguousInput          ErrorCode = "ambiguous_input"
	ErrRateLimited             ErrorCode = "rate_limited"
	ErrAuthorityUnavailable    ErrorCode = "authority_unavailable"
)

// ErrorCodes lists every PAP/1 error code.
func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrInvalidToken, ErrTokenExpired, ErrInvalidProof, ErrProofReplay, ErrUseNonce,
		ErrKeyMismatch, ErrBodyHashMismatch, ErrInstanceNotAdmitted, ErrAttestationInsufficient,
		ErrRunMismatch, ErrActionTampered, ErrUnknownRoute, ErrDefinitionInactive,
		ErrAmbiguousInput, ErrRateLimited, ErrAuthorityUnavailable,
	}
}

// Decision is an authorization decision (PAP/1 §7.1).
type Decision string

// The six PAP/1 decisions.
const (
	Allow                Decision = "ALLOW"
	AllowWithObligations Decision = "ALLOW_WITH_OBLIGATIONS"
	RequireApproval      Decision = "REQUIRE_APPROVAL"
	RequireStepUp        Decision = "REQUIRE_STEP_UP"
	Deny                 Decision = "DENY"
	CannotAuthorize      Decision = "CANNOT_AUTHORIZE"
)

// Permits reports whether the decision allows dispatch (subject to permit and
// commit-point checks). Every other decision MUST NOT dispatch.
func (d Decision) Permits() bool {
	return d == Allow || d == AllowWithObligations
}

// Holds reports whether the decision waits for a human requirement.
func (d Decision) Holds() bool {
	return d == RequireApproval || d == RequireStepUp
}

// Valid reports whether d is one of the six PAP/1 decisions.
func (d Decision) Valid() bool {
	switch d {
	case Allow, AllowWithObligations, RequireApproval, RequireStepUp, Deny, CannotAuthorize:
		return true
	default:
		return false
	}
}
