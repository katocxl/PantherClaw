// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// newVerification builds the server side of verification (G0 M7 track A):
// leases, reports and the expiry of leases and windows. Effect receipts are
// signed with the receipts key, like decision and execution receipts; notify
// (M5 notifications) tells admins about effects without a receipt.
func newVerification(pool *db.Pool, reg *keys.Registry, notify pgtransactions.Notifier) (*txapp.Service, error) {
	receipts, err := reg.Signer(keys.PurposeReceipts)
	if err != nil {
		return nil, err
	}
	return &txapp.Service{Store: &pgtransactions.Store{Pool: pool, Notify: notify}, Receipts: receipts}, nil
}
