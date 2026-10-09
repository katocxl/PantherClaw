// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

type fixture struct {
	pool   *db.Pool
	svc    *authority.Service
	reg    *keys.Registry
	gw     authority.Gateway
	budget ids.UUID

	ident            *iapp.Service
	runs             *runsapp.Service
	inv              *aapp.Inventory
	team, env, owner ids.UUID
	// wl is an admitted instance of a verified agent; run is bound to it.
	wl  workload
	run ids.UUID
}

// setupBase seeds an org with containment and a budget.
func setupBase(t *testing.T, limit string, maxCount *int32, ttl time.Duration) fixture {
	t.Helper()
	p := dbtest.New(t).AppPool(t)
	org := ids.New[ids.Org]()
	budget := ids.NewV7()
	lim := money.MustParse(limit)
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org); err != nil {
			return err
		}
		q := dbq.New(tx)
		if err := q.InsertContainment(ctx, org); err != nil {
			return err
		}
		return q.InsertBudget(ctx, dbq.InsertBudgetParams{OrgID: org, ID: budget, Name: "dev-refunds", Currency: "USD", LimitAmount: lim, MaxCount: maxCount})
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	for _, purpose := range []keys.Purpose{keys.PurposePermits, keys.PurposeReceipts} {
		k, _ := keys.GenerateSigningKey(purpose)
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	maxPer, _ := money.ParseMoney("100", "USD")
	svc := authority.New(p, reg, authority.Config{
		Grant:     domain.DevGrant{Name: "dev-refunds", Operation: actionir.OpRefundCreate, MaxPerAction: maxPer, BudgetName: "dev-refunds"},
		PermitTTL: ttl, Logger: pclog.Discard(),
	})
	return fixture{pool: p, svc: svc, reg: reg, gw: authority.Gateway{ID: "gw-dev-1", Org: org}, budget: budget}
}

func (f fixture) action(t *testing.T, amount string, run, act ids.UUID) []byte {
	t.Helper()
	return f.actionAs(t, amount, run, act, f.env.String(), f.wl.inst.Instance.String())
}

// actionAs is an action of instance in env.
func (f fixture) actionAs(t *testing.T, amount string, run, act ids.UUID, env, instance string) []byte {
	t.Helper()
	p, err := actionir.Encode(actionir.ActionIR{
		V: 1, Org: f.gw.Org.String(), Env: env, RunID: run.String(), ActionID: act.String(),
		AgentInstance: instance, Operation: actionir.OpRefundCreate,
		Definition: actionir.Definition{
			Package: "pc.mock-payments", Version: "1.0.0",
			Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		},
		Channel: "http", Route: "payments-refund", Target: actionir.Target{Type: "payments.charge", ID: "ch_1", Account: "acct_1"},
		Params: jsontext.Value(`{"amount":{"value":"` + amount + `","currency":"USD"},"reason":"duplicate"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.Canonical
}

func (f fixture) budgetRow(t *testing.T) dbq.GetBudgetRow {
	t.Helper()
	var b dbq.GetBudgetRow
	err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		b, err = dbq.New(tx).GetBudget(ctx, f.gw.Org, f.budget)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f fixture) authorize(t *testing.T, amount string) authority.Result {
	t.Helper()
	res, err := f.svc.Authorize(context.Background(), f.gw, f.action(t, amount, f.run, ids.NewV7()), f.creds(t, f.wl, f.wl.token))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestIntAllowDispatchCommit(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "30.00")
	if res.Decision != domain.Allow || res.Permit == "" || res.Receipt == "" {
		t.Fatalf("authorize = %+v", res)
	}
	// The permit verifies with the permits key only, and binds the action.
	v, _ := f.reg.Verifier(keys.PurposePermits, authority.TypePermit)
	payload, _, err := v.Verify(res.Permit)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Aud string `json:"aud"`
		Jti string `json:"jti"`
		Exp int64  `json:"exp"`
		Pap struct {
			Act   string `json:"act"`
			Epoch int64  `json:"epoch"`
			Txn   string `json:"txn"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != "gw:gw-dev-1" || claims.Jti != res.PermitID.String() || claims.Pap.Act != res.ActionHash ||
		claims.Pap.Epoch != res.Epoch || claims.Pap.Txn != res.TransactionID.String() {
		t.Fatalf("permit claims %+v do not bind the decision %+v", claims, res)
	}
	if ttl := time.Until(time.Unix(claims.Exp, 0)); ttl > 6*time.Second {
		t.Fatalf("permit lives %v, want ≈ 5s (HR-009)", ttl)
	}
	rv, _ := f.reg.Verifier(keys.PurposeReceipts, authority.TypeDecisionReceipt)
	if _, _, err := rv.Verify(res.Receipt); err != nil {
		t.Fatalf("decision receipt: %v", err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "30" || b.Spent.String() != "0" {
		t.Fatalf("after authorize: reserved %s spent %s", b.Reserved, b.Spent)
	}
	if err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(`{"id":"re_1"}`))
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{
		Permit: res.PermitID, Outcome: authority.Accepted, TargetStatus: 200, ResponseDigest: digest[:], DispatchMS: 12,
	}); err != nil {
		t.Fatal(err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "0" || b.Spent.String() != "30" || b.SpentCount != 1 {
		t.Fatalf("after commit: reserved %s spent %s count %d", b.Reserved, b.Spent, b.SpentCount)
	}
}

func TestHR009_PermitIsSingleUse(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "10.00")
	if err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch); !errors.Is(err, authority.ErrPermitUsed) {
		t.Fatalf("second BeginDispatch: %v, want ErrPermitUsed", err)
	}
	other := authority.Gateway{ID: "gw-other", Org: f.gw.Org}
	res2 := f.authorize(t, "10.00")
	if err := f.svc.BeginDispatch(ctx, other, res2.PermitID, res2.Epoch); !errors.Is(err, authority.ErrPermitUnknown) {
		t.Fatalf("another gateway used the permit: %v", err)
	}
}

func TestHR001_BeginDispatchRejectsStaleEpochAndKillSwitch(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "10.00")
	err := f.pool.InTenantTx(ctx, f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).BumpEpoch(ctx, f.gw.Org) // e.g. an agent was suspended (HR-002)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch); !errors.Is(err, authority.ErrEpochStale) {
		t.Fatalf("BeginDispatch after epoch bump: %v, want ErrEpochStale", err)
	}
	res2 := f.authorize(t, "10.00")
	err = f.pool.InTenantTx(ctx, f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).SetKillSwitch(ctx, true, f.gw.Org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.BeginDispatch(ctx, f.gw, res2.PermitID, res2.Epoch); !errors.Is(err, authority.ErrKillSwitch) {
		t.Fatalf("BeginDispatch under kill switch: %v", err)
	}
	if res := f.authorize(t, "10.00"); res.Decision != domain.Deny || res.Permit != "" {
		t.Fatalf("authorize under kill switch: %+v", res)
	}
}

func TestHR001_BeginDispatchRejectsExpiredPermit(t *testing.T) {
	f := setup(t, "1000", nil, time.Microsecond)
	res := f.authorize(t, "10.00")
	if err := f.svc.BeginDispatch(context.Background(), f.gw, res.PermitID, res.Epoch); !errors.Is(err, authority.ErrPermitExpired) {
		t.Fatalf("expired permit: %v, want ErrPermitExpired", err)
	}
}

func TestT012_SameActionDifferentHashIsTampered(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	ctx := context.Background()
	run, act := f.run, ids.NewV7()
	first, err := f.svc.Authorize(ctx, f.gw, f.action(t, "30.00", run, act), f.creds(t, f.wl, f.wl.token))
	if err != nil || first.Decision != domain.Allow {
		t.Fatalf("first = %+v, %v", first, err)
	}
	again, err := f.svc.Authorize(ctx, f.gw, f.action(t, "30.00", run, act), f.creds(t, f.wl, f.wl.token))
	if err != nil || again.Decision != domain.Allow || again.Permit != "" || again.TransactionID != first.TransactionID {
		t.Fatalf("retry returned %+v, %v; want the stored ALLOW without a second permit (HR-005)", again, err)
	}
	tampered, err := f.svc.Authorize(ctx, f.gw, f.action(t, "90.00", run, act), f.creds(t, f.wl, f.wl.token))
	if err != nil || tampered.Decision != domain.Deny || tampered.Reasons[0].Code != domain.ReasonActionTampered || tampered.Permit != "" {
		t.Fatalf("changed amount under the same action id: %+v, %v", tampered, err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "30" {
		t.Fatalf("reserved %s, want only the first 30", b.Reserved)
	}
}

func TestIntDenialsReserveNothing(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	if res := f.authorize(t, "125.00"); res.Decision != domain.Deny || res.Reasons[0].Code != domain.ReasonGrantAmountExceeded {
		t.Fatalf("$125 = %+v", res)
	}
	other := authority.Gateway{ID: f.gw.ID, Org: ids.New[ids.Org]()}
	res, err := f.svc.Authorize(context.Background(), other, f.action(t, "10.00", f.run, ids.NewV7()), f.creds(t, f.wl, f.wl.token))
	if err != nil || res.Decision != domain.Deny || res.Reasons[0].Code != domain.ReasonOrgMismatch {
		t.Fatalf("org mismatch = %+v, %v", res, err)
	}
	if res, _ := f.svc.Authorize(context.Background(), f.gw, []byte(`{"v":1}`), f.creds(t, f.wl, f.wl.token)); res.Decision != domain.CannotAuthorize {
		t.Fatalf("garbage = %+v", res)
	}
	if b := f.budgetRow(t); !b.Reserved.IsZero() {
		t.Fatalf("denials reserved %s", b.Reserved)
	}
}

func TestT011_NoOverspendUnder1000ConcurrentReservations(t *testing.T) {
	for name, tc := range map[string]struct {
		limit   string
		count   *int32
		allowed int
	}{
		"amount limit (3 × $30 ≤ $100)": {"100", nil, 3},
		"one refund":                    {"1000", ptr(int32(1)), 1},
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t, tc.limit, tc.count, 5*time.Second)
			var wg sync.WaitGroup
			var mu sync.Mutex
			counts := map[domain.Decision]int{}
			nonce, err := f.ident.Nonce(context.Background(), f.gw.Org)
			if err != nil {
				t.Fatal(err)
			}
			for range 1000 {
				c, action := f.credsWith(t, f.wl, f.wl.token, nonce), f.action(t, "30.00", f.run, ids.NewV7())
				wg.Go(func() {
					res, err := f.svc.Authorize(context.Background(), f.gw, action, c)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					counts[res.Decision]++
					mu.Unlock()
				})
			}
			wg.Wait()
			if counts[domain.Allow] != tc.allowed || counts[domain.Deny] != 1000-tc.allowed {
				t.Fatalf("decisions = %v, want %d ALLOW and %d DENY", counts, tc.allowed, 1000-tc.allowed)
			}
			b := f.budgetRow(t)
			want, _ := money.MustParse("30").MulInt(int64(tc.allowed))
			if !b.Reserved.Equal(want) || int(b.ReservedCount) != tc.allowed {
				t.Fatalf("reserved %s (%d), want %s (%d)", b.Reserved, b.ReservedCount, want, tc.allowed)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestT024_CrashMidDispatchYieldsUnknown(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "40.00")
	if err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch); err != nil {
		t.Fatal(err)
	}
	// The gateway "crashes": RecordExecution never arrives.
	r, err := f.svc.SweepOrg(ctx, f.gw.Org, 0)
	if err != nil || r.Unknown != 1 || r.Released != 0 {
		t.Fatalf("sweep = %+v, %v; want one UNKNOWN, nothing released", r, err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "40" {
		t.Fatalf("reservation released after a crash mid-dispatch: reserved %s (HR-003)", b.Reserved)
	}
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: res.PermitID, Outcome: authority.Accepted}); !errors.Is(err, authority.ErrNotDispatching) {
		t.Fatalf("late RecordExecution: %v, want ErrNotDispatching", err)
	}
}

func TestHR003_SweeperReleasesOnlyExpiredIssued(t *testing.T) {
	f := setup(t, "1000", nil, time.Microsecond)
	ctx := context.Background()
	for _, amount := range []string{"25.00", "10.50", "4.25"} {
		f.authorize(t, amount)
	}
	r, err := f.svc.SweepOrg(ctx, f.gw.Org, time.Hour)
	if err != nil || r.Released != 3 || r.Unknown != 0 {
		t.Fatalf("sweep = %+v, %v", r, err)
	}
	if b := f.budgetRow(t); !b.Reserved.IsZero() || b.ReservedCount != 0 {
		t.Fatalf("expired permit's reservation not released: %s", b.Reserved)
	}
	if r, _ := f.svc.SweepOrg(ctx, f.gw.Org, time.Hour); r.Released != 0 {
		t.Fatal("sweeper released twice")
	}
}

func TestIntFailedDispatchReleases(t *testing.T) {
	f := setup(t, "1000", nil, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "20.00")
	if err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: res.PermitID, Outcome: authority.Failed, TargetStatus: 402}); err != nil {
		t.Fatal(err)
	}
	if b := f.budgetRow(t); !b.Reserved.IsZero() || !b.Spent.IsZero() {
		t.Fatalf("after failure: reserved %s spent %s", b.Reserved, b.Spent)
	}
}
