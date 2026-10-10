// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package trust

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// The development package key (HR-163). `pantherclaw-server dev seed` keeps
// one in deploy/dev/secrets so that a developer can import packages through
// the API of a local server. It signs the same targets format as a package
// root, PantherClaw's reserved names included, but its kid starts with
// DevKIDPrefix: ParseRoots never accepts it, so it can never be embedded as
// a package root, and only a server whose configuration keeps every
// listener on loopback adds it to the roots it verifies with.

// DevKIDPrefix starts the kid of a development package key.
const DevKIDPrefix = "packages-dev-"

// DevKID derives the kid of a development package public key; it equals
// rootkey.KID(rootkey.PurposeDevPackages, pub).
func DevKID(pub ed25519.PublicKey) string { return DevKIDPrefix + jws.Thumbprint(pub)[:22] }

// IsDevKID reports whether kid names a development package key.
func IsDevKID(kid string) bool { return strings.HasPrefix(kid, DevKIDPrefix) }

// ParseDevKey parses the public JWKS of a development package key: exactly
// one Ed25519 signing key, whose kid is the one derived from it.
func ParseDevKey(b []byte) (Roots, error) {
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("trust: development key: %w", err)
	}
	if len(doc.Keys) != 1 {
		return nil, errors.New("trust: development key: want exactly one key")
	}
	k := doc.Keys[0]
	pub, err := k.Key()
	if err != nil {
		return nil, fmt.Errorf("trust: development key: %w", err)
	}
	if k.Kid != DevKID(pub) {
		return nil, fmt.Errorf("trust: development key: kid %q is not %s", k.Kid, DevKID(pub))
	}
	return Roots{k.Kid: pub}, nil
}
