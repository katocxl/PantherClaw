// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package trust

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Org package-signing keys (HR-162, Team edition). An org signs its own
// packages with an Ed25519 key whose public half an org admin registered.
// Such a key signs the same targets format as the package root, but its kid
// starts with OrgKIDPrefix, so the two can never be confused, and it may
// not list a name in PantherClaw's reserved namespace.
const (
	// OrgKIDPrefix starts every org package-signing key kid.
	OrgKIDPrefix = "org-packages-"
	// ReservedPrefix starts the package names only a package root may sign.
	ReservedPrefix = "pc."
)

// OrgKID derives the kid of an org package-signing public key.
func OrgKID(pub ed25519.PublicKey) string { return OrgKIDPrefix + jws.Thumbprint(pub)[:22] }

// IsOrgKID reports whether kid names an org package-signing key rather than
// a package root. Only the prefix is read: the key itself still has to be
// one the org registered.
func IsOrgKID(kid string) bool { return strings.HasPrefix(kid, OrgKIDPrefix) }

// Reserved reports whether a package name belongs to PantherClaw's
// namespace, which only a package root may sign.
func Reserved(name string) bool { return strings.HasPrefix(name, ReservedPrefix) }

// ParseOrgKey parses the public JWK of an org package-signing key. It must
// be an Ed25519 signing key; a kid, when present, must be the one derived
// from the key. It returns the derived kid.
func ParseOrgKey(b []byte) (string, ed25519.PublicKey, error) {
	var k jws.JWK
	if err := json.Unmarshal(b, &k, json.RejectUnknownMembers(true)); err != nil {
		return "", nil, untrusted("org key: %v", err)
	}
	pub, err := k.Key()
	if err != nil {
		return "", nil, untrusted("org key: %v", err)
	}
	kid := OrgKID(pub)
	switch {
	case k.Kid != "" && k.Kid != kid:
		return "", nil, untrusted("org key: kid %q does not match its key (%s)", k.Kid, kid)
	case k.Use != "" && k.Use != "sig":
		return "", nil, untrusted("org key: use %q, want sig", k.Use)
	}
	return kid, pub, nil
}

// checkSigner reports whether kid may sign targets: a package root, or an
// org key, each with the kid derived from its own key.
func checkSigner(kid string, pub ed25519.PublicKey) error {
	if kid == RootKID(pub) || kid == OrgKID(pub) {
		return nil
	}
	return fmt.Errorf("trust: signing key %q is neither a package root nor an org package-signing key", kid)
}

// checkNamespace refuses targets signed by an org key that list a reserved
// name (HR-162).
func (t Targets) checkNamespace(kid string) error {
	if !IsOrgKID(kid) {
		return nil
	}
	for key := range t.Targets {
		if name, _, _ := strings.Cut(key, "@"); Reserved(name) {
			return untrusted("an org package-signing key cannot sign %q: names starting with %q are PantherClaw's", key, ReservedPrefix)
		}
	}
	return nil
}
