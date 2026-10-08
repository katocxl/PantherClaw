// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package keystore persists PantherClaw's keys in PostgreSQL (SB-3,
// ADR-0012): platform signing keys under the reserved platform org, and
// per-org data encryption keys. Private material is stored only wrapped by
// a KEK from keys.KeyProvider; the wrap AAD binds org, purpose and key
// identity, so wrapped keys cannot be moved between rows (HR-062).
// Creation, rotation and revocation are recorded as platform-audit events
// in the same transaction (SB-4, fail closed).
package keystore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Actor is recorded on keystore audit events.
var Actor = domain.Actor{Type: "system", ID: "keystore"}

func signingAAD(org ids.OrgID, purpose keys.Purpose, kid string) []byte {
	return []byte("pc-signing-key-v1|" + org.String() + "|" + string(purpose) + "|" + kid)
}

// LoadSigningKeys loads every non-revoked platform signing key into reg,
// creating an active key for each purpose that has none. Unwrapping fails
// closed: a key that cannot be unwrapped stops the load.
func LoadSigningKeys(ctx context.Context, pool *db.Pool, kp keys.KeyProvider, reg *keys.Registry) error {
	org := ids.PlatformOrg
	return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListSigningKeys(ctx, org)
		if err != nil {
			return err
		}
		active := map[keys.Purpose]bool{}
		for _, r := range rows {
			k := keys.SigningKey{KID: r.Kid, Purpose: keys.Purpose(r.Purpose), State: keys.State(r.State), Public: ed25519.PublicKey(r.PublicKey)}
			if k.State == keys.StateActive {
				seed, err := kp.Unwrap(ctx, r.WrappedPrivateKey, signingAAD(org, k.Purpose, k.KID))
				if err != nil {
					return fmt.Errorf("keystore: unwrap signing key %s: %w", k.KID, err)
				}
				if len(seed) != ed25519.SeedSize {
					return fmt.Errorf("keystore: signing key %s has a malformed seed", k.KID)
				}
				k.Private = pclog.NewSecret(ed25519.NewKeyFromSeed(seed))
				active[k.Purpose] = true
			}
			if err := reg.Put(k); err != nil {
				return fmt.Errorf("keystore: %w", err)
			}
		}
		for _, p := range keys.Purposes() {
			if active[p] {
				continue
			}
			k, err := createSigningKey(ctx, tx, kp, p)
			if err != nil {
				return err
			}
			if err := reg.Put(k); err != nil {
				return fmt.Errorf("keystore: %w", err)
			}
		}
		return nil
	})
}

func createSigningKey(ctx context.Context, tx db.TenantTx, kp keys.KeyProvider, p keys.Purpose) (keys.SigningKey, error) {
	k, err := keys.GenerateSigningKey(p)
	if err != nil {
		return keys.SigningKey{}, err
	}
	wrapped, err := kp.Wrap(ctx, k.Private.Reveal().Seed(), signingAAD(tx.OrgID(), p, k.KID))
	if err != nil {
		return keys.SigningKey{}, fmt.Errorf("keystore: wrap: %w", err)
	}
	if err := dbq.New(tx).InsertSigningKey(ctx, dbq.InsertSigningKeyParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), Kid: k.KID, Purpose: string(p),
		PublicKey: k.Public, WrappedPrivateKey: wrapped, KekID: kp.CurrentKEK(),
	}); err != nil {
		return keys.SigningKey{}, fmt.Errorf("keystore: insert signing key: %w", err)
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "signing_key.created", Actor: Actor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "signing_key", ID: k.KID},
		Details: map[string]string{"purpose": string(p), "kek_id": kp.CurrentKEK()},
	}); err != nil {
		return keys.SigningKey{}, err
	}
	return k, nil
}

// ErrNotFound reports a missing key.
var ErrNotFound = errors.New("keystore: key not found")

// RotateSigningKey moves the active key of purpose to RETIRING (it keeps
// verifying during the overlap) and creates a new active key. Reload the
// registry afterwards.
func RotateSigningKey(ctx context.Context, pool *db.Pool, kp keys.KeyProvider, p keys.Purpose, actor domain.Actor) (newKID string, err error) {
	if !p.Valid() {
		return "", fmt.Errorf("keystore: unknown purpose %q", p)
	}
	org := ids.PlatformOrg
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListSigningKeys(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Purpose == string(p) && r.State == string(keys.StateActive) {
				if err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
					OrgID: org, Kid: r.Kid, FromState: string(keys.StateActive), ToState: string(keys.StateRetiring),
				})); err != nil {
					return err
				}
				if _, err := audit.Record(ctx, tx, audit.Event{
					Name: "signing_key.retiring", Actor: actor, Outcome: audit.Success,
					Object: &audit.Object{Type: "signing_key", ID: r.Kid}, Details: map[string]string{"purpose": r.Purpose},
				}); err != nil {
					return err
				}
			}
		}
		k, err := createSigningKey(ctx, tx, kp, p)
		if err != nil {
			return err
		}
		newKID = k.KID
		return nil
	})
	return newKID, err
}

// RevokeSigningKey revokes a retiring key (an active key must be rotated
// first, so a purpose is never left without a signer by accident).
func RevokeSigningKey(ctx context.Context, pool *db.Pool, kid string, actor domain.Actor) error {
	org := ids.PlatformOrg
	return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
			OrgID: org, Kid: kid, FromState: string(keys.StateRetiring), ToState: string(keys.StateRevoked),
		}))
		if errors.Is(err, db.ErrLostRace) {
			return fmt.Errorf("%w: no retiring key %q", ErrNotFound, kid)
		}
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "signing_key.revoked", Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "signing_key", ID: kid},
		})
		return err
	})
}
