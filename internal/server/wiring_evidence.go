// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// mountEvidenceKeys serves evidence-keys.json and revoked-keys.json
// (PAP-1 §11, G0 M7): public, from the keystore, without private material.
func mountEvidenceKeys(mux *http.ServeMux, d apiDeps) {
	pool := d.pool
	keydocs.New(func(ctx context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		return keystore.PublishedKeys(ctx, pool, ps)
	}, d.publicURL, d.logOrigin, clock.System{}, d.log).Mount(mux)
}
