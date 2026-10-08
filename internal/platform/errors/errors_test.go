// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package errors

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"testing"
)

var errSentinel = New(Aborted, "LOST_RACE", "concurrent update")

func TestWrapKeepsCauseOutOfPublicMessage(t *testing.T) {
	cause := stderrors.New(`pq: relation "secret_table" does not exist`)
	err := Wrap(cause, NotFound, "ORG_NOT_FOUND", "organization not found")
	if got := PublicMessage(err); got != "organization not found" {
		t.Fatalf("PublicMessage = %q", got)
	}
	if !strings.Contains(err.Error(), "secret_table") {
		t.Fatalf("Error() should include the cause for logs: %q", err.Error())
	}
	if !stderrors.Is(err, cause) {
		t.Fatal("cause not reachable through Unwrap")
	}
}

func TestInternalNeverLeaks(t *testing.T) {
	for _, err := range []error{
		stderrors.New("dial tcp 10.0.0.5:5432: connection refused"),
		Wrap(stderrors.New("stack trace here"), Internal, "BUG", "nil map at handler.go:42"),
		fmt.Errorf("wrapped: %w", stderrors.New("password=hunter2")),
	} {
		if got := PublicMessage(err); got != internalMessage {
			t.Errorf("PublicMessage(%v) = %q, want %q", err, got, internalMessage)
		}
		if CodeOf(err) != Internal {
			t.Errorf("CodeOf(%v) = %q, want internal", err, CodeOf(err))
		}
	}
}

func TestCodeOfThroughWrapping(t *testing.T) {
	err := fmt.Errorf("finalize: %w", New(Deny, "GRANT_EXPIRED", "grant expired"))
	if CodeOf(err) != Deny {
		t.Fatalf("CodeOf = %q, want deny", CodeOf(err))
	}
	if ReasonOf(err) != "GRANT_EXPIRED" {
		t.Fatalf("ReasonOf = %q", ReasonOf(err))
	}
	if PublicMessage(err) != "grant expired" {
		t.Fatalf("PublicMessage = %q", PublicMessage(err))
	}
}

func TestContextErrors(t *testing.T) {
	if got := CodeOf(fmt.Errorf("query: %w", context.DeadlineExceeded)); got != DeadlineExceeded {
		t.Fatalf("deadline → %q", got)
	}
	if got := CodeOf(context.Canceled); got != Canceled {
		t.Fatalf("canceled → %q", got)
	}
	if got := PublicMessage(context.Canceled); got != "request canceled" {
		t.Fatalf("PublicMessage(canceled) = %q", got)
	}
}

func TestSentinelMatchesByCodeAndReason(t *testing.T) {
	err := Wrap(stderrors.New("0 rows"), Aborted, "LOST_RACE", "permit already consumed")
	if !stderrors.Is(err, errSentinel) {
		t.Fatal("same code+reason should match the sentinel")
	}
	other := New(Aborted, "OTHER", "x")
	if stderrors.Is(other, errSentinel) {
		t.Fatal("different reason must not match")
	}
	if stderrors.Is(stderrors.New("LOST_RACE"), errSentinel) {
		t.Fatal("plain errors must not match")
	}
}

func TestNilError(t *testing.T) {
	if CodeOf(nil) != "" || PublicMessage(nil) != "" || ReasonOf(nil) != "" {
		t.Fatal("nil error should have empty code, message and reason")
	}
}

func TestCodesAreUniqueSnakeCase(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range Codes() {
		if seen[c] {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = true
		if strings.ToLower(string(c)) != string(c) || strings.ContainsAny(string(c), " -") {
			t.Fatalf("code %q is not lower snake_case", c)
		}
	}
}
