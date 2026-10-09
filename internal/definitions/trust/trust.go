// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package trust verifies TUF-style signed metadata for tool packages
// (HR-123, T-036).
//
// The offline package root (`pclaw-admin keygen --purpose packages`) signs
// one targets document: a monotonic version, an expiry, and for each
// "name@version" the length and SHA-256 of the exact package file bytes.
// The signature is a compact JWS (EdDSA only, typ "pc-package-targets+jwt")
// verified against the root public keys embedded in roots.json. There are no
// snapshot or timestamp roles: they would need online keys. Freshness comes
// from the expiry and from refusing a version lower than the last one seen
// (rollback) or different content under the same version (equivocation).
//
// Until the founder commits the offline public key (Day-0 item 6), roots.json
// is empty and no package root verifies.
//
// An org's own packages are signed with an org package-signing key instead
// (HR-162, orgkeys.go): the same format, verified only against the keys
// that org registered.
package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

const (
	// JOSEType is the JWS typ of a targets document.
	JOSEType = "pc-package-targets+jwt"
	// KIDPrefix starts every package root kid.
	KIDPrefix = "packages-root-"
	// Spec names the metadata format.
	Spec = "pc-tuf-1"
	// MaxTargets bounds one targets document (it must fit one compact JWS).
	MaxTargets = 256
)

//go:embed roots.json
var embeddedRoots []byte

var (
	// ErrUntrusted reports metadata or a package that does not verify. The
	// wrapped detail is for operators; the effect is always the same.
	ErrUntrusted = errors.New("trust: untrusted package metadata")
	// ErrExpired reports metadata past its expiry.
	ErrExpired = errors.New("trust: package metadata has expired")
	// ErrRollback reports metadata older than the last trusted version, or
	// different metadata under the same version.
	ErrRollback = errors.New("trust: package metadata rollback")
)

// Target lists one package file.
type Target struct {
	Length int64             `json:"length"`
	Hashes map[string]string `json:"hashes"`
}

// Targets is the signed targets document.
type Targets struct {
	Type    string            `json:"_type"`
	Spec    string            `json:"spec"`
	Version int64             `json:"version"`
	Expires string            `json:"expires"`
	Targets map[string]Target `json:"targets"`
}

// Verified is a targets document whose signature, shape and expiry checked
// out, with the SHA-256 of its payload (to detect equivocation).
type Verified struct {
	Targets
	Expiry        time.Time
	PayloadDigest string
	KID           string
}

// Roots are trusted package root public keys by kid.
type Roots map[string]ed25519.PublicKey

// EmbeddedRoots returns the roots compiled into this binary.
func EmbeddedRoots() (Roots, error) { return ParseRoots(embeddedRoots) }

// RootKID derives the kid of a package root public key; it equals
// rootkey.KID(rootkey.PurposePackages, pub).
func RootKID(pub ed25519.PublicKey) string { return KIDPrefix + jws.Thumbprint(pub)[:22] }

// ParseRoots parses a JWKS of Ed25519 public keys whose kids are derived
// from the keys themselves.
func ParseRoots(b []byte) (Roots, error) {
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("trust: roots: %w", err)
	}
	roots := Roots{}
	for _, k := range doc.Keys {
		pub, err := k.Key()
		if err != nil {
			return nil, fmt.Errorf("trust: roots: %w", err)
		}
		if k.Kid != RootKID(pub) {
			return nil, fmt.Errorf("trust: roots: kid %q does not match its key", k.Kid)
		}
		roots[k.Kid] = pub
	}
	return roots, nil
}

func untrusted(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUntrusted}, args...)...)
}

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Key returns the targets key of a package version: "name@version".
func Key(name, version string) string { return name + "@" + version }

func (t Targets) validate() (time.Time, error) {
	if t.Type != "targets" || t.Spec != Spec || t.Version < 1 {
		return time.Time{}, untrusted("not a %s targets document with a positive version", Spec)
	}
	exp, err := time.Parse(time.RFC3339, t.Expires)
	if err != nil || !strings.HasSuffix(t.Expires, "Z") {
		return time.Time{}, untrusted("expires must be an RFC 3339 UTC time")
	}
	if len(t.Targets) == 0 || len(t.Targets) > MaxTargets {
		return time.Time{}, untrusted("1..%d targets", MaxTargets)
	}
	for _, key := range slices.Sorted(maps.Keys(t.Targets)) {
		name, version, ok := strings.Cut(key, "@")
		tg := t.Targets[key]
		if !ok || !actionir.ValidPackage(name) || !actionir.ValidVersion(version) {
			return time.Time{}, untrusted("target %q is not name@version", key)
		}
		if tg.Length < 1 || tg.Length > manifest.MaxBytes || len(tg.Hashes) != 1 || !hexDigest.MatchString(tg.Hashes["sha256"]) {
			return time.Time{}, untrusted("target %q needs a length and exactly one sha256 hash", key)
		}
	}
	return exp, nil
}

// Sign produces a targets document. It runs offline: in pclaw-admin with
// the package root, or in pclaw with an org package-signing key.
func Sign(t Targets, signer *jws.Signer) (string, error) {
	if err := checkSigner(signer.KeyID(), signer.Public()); err != nil {
		return "", err
	}
	t.Type, t.Spec = "targets", Spec
	if _, err := t.validate(); err != nil {
		return "", err
	}
	if err := t.checkNamespace(signer.KeyID()); err != nil {
		return "", err
	}
	payload, err := json.Marshal(t, json.Deterministic(true))
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return signer.Sign(JOSEType, payload)
}

// Verify checks a targets document against roots and its expiry at now.
// roots are either package roots or one org's registered package-signing
// keys; a document signed by an org key must not list a reserved name.
func Verify(doc string, roots Roots, now time.Time) (Verified, error) {
	if len(roots) == 0 {
		return Verified{}, untrusted("no package root keys are embedded in this build")
	}
	v, err := jws.NewVerifier(JOSEType, roots)
	if err != nil {
		return Verified{}, untrusted("%v", err)
	}
	payload, kid, err := v.Verify(strings.TrimSpace(doc))
	if err != nil {
		return Verified{}, untrusted("signature: %v", err)
	}
	var t Targets
	if err := json.Unmarshal(payload, &t, json.RejectUnknownMembers(true)); err != nil {
		return Verified{}, untrusted("payload: %v", err)
	}
	exp, err := t.validate()
	if err != nil {
		return Verified{}, err
	}
	if err := t.checkNamespace(kid); err != nil {
		return Verified{}, err
	}
	if !now.Before(exp) {
		return Verified{}, fmt.Errorf("%w: version %d expired at %s", ErrExpired, t.Version, t.Expires)
	}
	sum := sha256.Sum256(payload)
	return Verified{Targets: t, Expiry: exp, PayloadDigest: hex.EncodeToString(sum[:]), KID: kid}, nil
}

// State is the last trusted targets metadata for an installation.
type State struct {
	Version       int64
	PayloadDigest string
}

// CheckAdvance refuses metadata older than the last trusted version, or
// different metadata under the same version (HR-123). A nil last means no
// metadata was trusted before.
func CheckAdvance(last *State, next Verified) error {
	switch {
	case last == nil:
		return nil
	case next.Version < last.Version:
		return fmt.Errorf("%w: version %d is older than the trusted %d", ErrRollback, next.Version, last.Version)
	case next.Version == last.Version && next.PayloadDigest != last.PayloadDigest:
		return fmt.Errorf("%w: different metadata under version %d", ErrRollback, next.Version)
	}
	return nil
}

// TargetOf lists one package file for signing: its "name@version" key, read
// from the decoded package, and the length and SHA-256 of its exact bytes.
func TargetOf(raw []byte) (string, Target, error) {
	p, err := manifest.Decode(raw)
	if err != nil {
		return "", Target{}, err
	}
	sum := sha256.Sum256(raw)
	return Key(p.Name, p.Version), Target{Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}}, nil
}

// Match checks that raw is exactly the listed file for name@version and
// returns its file digest.
func (v Verified) Match(name, version string, raw []byte) (string, error) {
	tg, ok := v.Targets.Targets[Key(name, version)]
	if !ok {
		return "", untrusted("%s is not listed in targets version %d", Key(name, version), v.Version)
	}
	sum := sha256.Sum256(raw)
	want, err := hex.DecodeString(tg.Hashes["sha256"])
	if err != nil || int64(len(raw)) != tg.Length || subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return "", untrusted("%s does not match its signed length and hash", Key(name, version))
	}
	return manifest.FileDigest(raw), nil
}
