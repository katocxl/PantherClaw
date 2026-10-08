// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// Limits shared with the migrations and protos.
const (
	MaxNameLen        = 200
	MaxDescriptionLen = 1000
	MaxEmailLen       = 320
)

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidSlug reports whether s is a lowercase DNS-label-like identifier.
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

// CheckSlug returns InvalidArgument unless s is a valid slug.
func CheckSlug(field, s string) error {
	if !ValidSlug(s) {
		return pcerr.New(pcerr.InvalidArgument, "INVALID_SLUG",
			field+" must be 1-63 lowercase letters, digits or hyphens, starting and ending with a letter or digit")
	}
	return nil
}

// CheckName validates a display name: 1-200 characters after trimming, valid
// UTF-8, no control or bidirectional formatting characters.
func CheckName(field, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > MaxNameLen || !plainText(s, false) {
		return "", pcerr.New(pcerr.InvalidArgument, "INVALID_NAME",
			field+" must be 1-200 printable characters")
	}
	return s, nil
}

// CheckDescription validates an optional description (newlines allowed).
func CheckDescription(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > MaxDescriptionLen || !plainText(s, true) {
		return "", pcerr.New(pcerr.InvalidArgument, "INVALID_DESCRIPTION",
			"description must be at most 1000 printable characters")
	}
	return s, nil
}

// plainText rejects invalid UTF-8, control characters and Unicode format
// characters (bidirectional overrides, zero-width joiners), which can make
// names display differently from what they are (log and UI spoofing).
func plainText(s string, newlines bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if newlines && r == '\n' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// SanitizeClaim makes an IdP-supplied string (email, display name) safe to
// store and show: control and format characters are dropped and the result
// is cut to maxRunes. IdP claims are trusted for identity, not for content.
func SanitizeClaim(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// NormalizeEmail lowercases and trims an email address for comparison. It
// does not try to validate deliverability.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// CheckEmail validates an invitation email address.
func CheckEmail(s string) (string, error) {
	e := NormalizeEmail(s)
	at := strings.LastIndexByte(e, '@')
	if at < 1 || at == len(e)-1 || len(e) > MaxEmailLen || !plainText(e, false) || strings.ContainsAny(e, " \t<>\"") {
		return "", pcerr.New(pcerr.InvalidArgument, "INVALID_EMAIL", "email must be an address like name@example.com")
	}
	return e, nil
}

// EnvironmentKind classifies an environment (F578).
type EnvironmentKind string

// Environment kinds.
const (
	Development EnvironmentKind = "DEVELOPMENT"
	Staging     EnvironmentKind = "STAGING"
	Production  EnvironmentKind = "PRODUCTION"
)

// Valid reports whether k is a known kind.
func (k EnvironmentKind) Valid() bool {
	return k == Development || k == Staging || k == Production
}

// State is the lifecycle state of hierarchy entities.
type State string

// Hierarchy states. Archived entities are kept for history; nothing new can
// be attached to them.
const (
	Active   State = "ACTIVE"
	Archived State = "ARCHIVED"
)

// AccountState is the state of a user or service account.
type AccountState string

// Account states. A disabled account cannot authenticate; its sessions and
// tokens stop working at the next request.
const (
	Enabled  AccountState = "ACTIVE"
	Disabled AccountState = "DISABLED"
)
