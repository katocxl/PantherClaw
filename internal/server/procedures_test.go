// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestProcedurePermissionsMatchProtos: the interceptor's table is exactly
// the set of procedures and permissions declared in the protos (BUILD_GUIDE
// §3.2), so a new rpc cannot be served without a permission decision.
func TestProcedurePermissionsMatchProtos(t *testing.T) {
	declared, err := protoperms.Declared(filepath.Join("..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	for proc, perm := range declared {
		if got, ok := procedurePermissions[proc]; !ok || string(got) != perm {
			t.Errorf("%s: table has %q, proto declares %q", proc, got, perm)
		}
	}
	for proc := range procedurePermissions {
		if _, ok := declared[proc]; !ok {
			t.Errorf("%s is in the table but not in any proto", proc)
		}
	}
	var public []string
	for proc, perm := range procedurePermissions {
		if perm == td.PermPublic {
			public = append(public, proc)
		}
	}
	if want := publicProcedures(); !slices.Equal(slices.Sorted(slices.Values(public)), slices.Sorted(slices.Values(want))) {
		t.Errorf("public procedures %v, server exposes %v", public, want)
	}
	if len(slices.Collect(maps.Keys(procedurePermissions))) < 46 {
		t.Fatalf("table has %d procedures", len(procedurePermissions))
	}
}
