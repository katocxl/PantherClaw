// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// TestMockPaymentsPinMatchesThePackage: the route pins the refund
// definition of the reference package; a pin that drifts from the package
// would make every refund CANNOT_AUTHORIZE (DEFINITION_NOT_PINNED).
func TestMockPaymentsPinMatchesThePackage(t *testing.T) {
	pkg, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := pkg.Definition(actionir.OpRefundCreate)
	if !ok {
		t.Fatal("the package defines no refund")
	}
	if mockPayments.Package != pkg.Name || mockPayments.Version != pkg.Version || mockPayments.Digest != d.Digest {
		t.Fatalf("pin %+v, package %s@%s %s", mockPayments, pkg.Name, pkg.Version, d.Digest)
	}
}
