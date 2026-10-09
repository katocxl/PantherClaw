// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packagesrpc

import (
	"context"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/definitions/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
)

// Org package-signing keys (HR-162, ADR-0020).

var (
	keyStates = map[app.KeyState]pantherclawv1.SigningKeyState{
		app.KeyActive:  pantherclawv1.SigningKeyState_SIGNING_KEY_STATE_ACTIVE,
		app.KeyRevoked: pantherclawv1.SigningKeyState_SIGNING_KEY_STATE_REVOKED,
	}
	revokeReasons = map[app.RevokeReason]pantherclawv1.SigningKeyRevokeReason{
		app.RevokeRotated:     pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_ROTATED,
		app.RevokeCompromised: pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_COMPROMISED,
	}
	reasonOf = map[pantherclawv1.SigningKeyRevokeReason]app.RevokeReason{
		pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_ROTATED:     app.RevokeRotated,
		pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_COMPROMISED: app.RevokeCompromised,
	}
)

// KeyProto renders a signing key (its public half only).
func KeyProto(k app.SigningKey) *pantherclawv1.SigningKey {
	out := &pantherclawv1.SigningKey{
		Kid: k.KID, Name: k.Name, State: keyStates[k.State], RevokeReason: revokeReasons[k.Reason],
		CreatedBy: k.CreatedBy, CreateTime: ts(k.CreatedAt), RevokedBy: k.RevokedBy, RevokeTime: ts(k.RevokedAt),
	}
	if jwk, err := json.Marshal(jws.PublicJWK(k.Public, k.KID)); err == nil {
		out.PublicJwk = string(jwk)
	}
	if k.Metadata != nil {
		out.MetadataVersion = k.Metadata.Version
	}
	return out
}

// RegisterSigningKey implements PackageServiceHandler.
func (s *Packages) RegisterSigningKey(ctx context.Context, req *pantherclawv1.RegisterSigningKeyRequest) (*pantherclawv1.RegisterSigningKeyResponse, error) {
	k, err := s.svc.RegisterKey(ctx, req.GetName(), []byte(req.GetPublicJwk()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RegisterSigningKeyResponse{Key: KeyProto(k)}, nil
}

// RevokeSigningKey implements PackageServiceHandler.
func (s *Packages) RevokeSigningKey(ctx context.Context, req *pantherclawv1.RevokeSigningKeyRequest) (*pantherclawv1.RevokeSigningKeyResponse, error) {
	k, moved, err := s.svc.RevokeKey(ctx, req.GetKid(), reasonOf[req.GetReason()])
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.RevokeSigningKeyResponse{Key: KeyProto(k)}
	for _, m := range moved {
		out.Withdrawn = append(out.Withdrawn, &pantherclawv1.PackageVersion{Name: m.Name, Version: m.Version, State: states[m.To], SigningKey: k.KID})
	}
	return out, nil
}

// ListSigningKeys implements PackageServiceHandler.
func (s *Packages) ListSigningKeys(ctx context.Context, _ *pantherclawv1.ListSigningKeysRequest) (*pantherclawv1.ListSigningKeysResponse, error) {
	keys, err := s.svc.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSigningKeysResponse{}
	for _, k := range keys {
		out.Keys = append(out.Keys, KeyProto(k))
	}
	return out, nil
}
