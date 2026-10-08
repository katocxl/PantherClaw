// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package errors defines PantherClaw's stable, client-visible error codes.
//
// An *Error carries three things: a Code (a stable category that adapters map
// to RPC/HTTP status), a Reason (a stable UPPER_SNAKE machine reason such as
// LICENCE_EXPIRED) and a client-safe message. The wrapped cause is for logs
// only and is never shown to clients, so internal details cannot leak through
// API errors (BUILD_GUIDE §3.1, SB-8).
//
// Import it with an alias, for example:
//
//	import pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
package errors

import (
	"context"
	stderrors "errors"
)

// Code is a stable error category.
type Code string

// Error codes. Security decisions surface as their precise decision rather
// than as a generic failure.
const (
	InvalidArgument    Code = "invalid_argument"
	NotFound           Code = "not_found"
	AlreadyExists      Code = "already_exists"
	PermissionDenied   Code = "permission_denied"
	Unauthenticated    Code = "unauthenticated"
	FailedPrecondition Code = "failed_precondition"
	Aborted            Code = "aborted" // lost race or conflict; the caller may re-read and retry
	ResourceExhausted  Code = "resource_exhausted"
	Canceled           Code = "canceled"
	DeadlineExceeded   Code = "deadline_exceeded"
	Unavailable        Code = "unavailable"
	Unimplemented      Code = "unimplemented"
	Internal           Code = "internal"
	Deny               Code = "deny"             // a known prohibition (fail closed)
	CannotAuthorize    Code = "cannot_authorize" // missing evidence or dependency (fail closed, retryable)
)

// Codes lists every defined code.
func Codes() []Code {
	return []Code{
		InvalidArgument, NotFound, AlreadyExists, PermissionDenied, Unauthenticated,
		FailedPrecondition, Aborted, ResourceExhausted, Canceled, DeadlineExceeded,
		Unavailable, Unimplemented, Internal, Deny, CannotAuthorize,
	}
}

// internalMessage is the only message clients see for internal failures.
const internalMessage = "internal error"

// Error is a PantherClaw error. Construct it with New or Wrap.
type Error struct {
	code   Code
	reason string
	msg    string
	cause  error
}

// New returns an error with a code, a stable reason and a client-safe message.
func New(code Code, reason, msg string) *Error {
	return &Error{code: code, reason: reason, msg: msg}
}

// Wrap returns an error that records cause for logs while presenting only the
// code, reason and message to clients.
func Wrap(cause error, code Code, reason, msg string) *Error {
	return &Error{code: code, reason: reason, msg: msg, cause: cause}
}

// Error returns the full description, including the cause, for logs.
func (e *Error) Error() string {
	s := string(e.code)
	if e.reason != "" {
		s += " " + e.reason
	}
	if e.msg != "" {
		s += ": " + e.msg
	}
	if e.cause != nil {
		s += ": " + e.cause.Error()
	}
	return s
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.cause }

// Is matches another *Error with the same code and reason, so package-level
// sentinel values work with errors.Is even when wrapped with a cause.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.code == t.code && e.reason == t.reason
}

// Code returns the error code.
func (e *Error) Code() Code { return e.code }

// Reason returns the stable machine reason.
func (e *Error) Reason() string { return e.reason }

// Message returns the client-safe message.
func (e *Error) Message() string { return e.msg }

// CodeOf returns the code of the first *Error in err's chain. Context
// cancellation and deadlines map to their codes; anything else is Internal.
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	if e, ok := stderrors.AsType[*Error](err); ok {
		return e.code
	}
	switch {
	case stderrors.Is(err, context.DeadlineExceeded):
		return DeadlineExceeded
	case stderrors.Is(err, context.Canceled):
		return Canceled
	default:
		return Internal
	}
}

// ReasonOf returns the reason of the first *Error in err's chain, or "".
func ReasonOf(err error) string {
	if e, ok := stderrors.AsType[*Error](err); ok {
		return e.reason
	}
	return ""
}

// PublicMessage returns the message that may be shown to a client. Internal
// errors and errors that are not *Error never expose their text.
func PublicMessage(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := stderrors.AsType[*Error](err); ok && e.code != Internal {
		return e.msg
	}
	code := CodeOf(err)
	if code == DeadlineExceeded {
		return "deadline exceeded"
	}
	if code == Canceled {
		return "request canceled"
	}
	return internalMessage
}
