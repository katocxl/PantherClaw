// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package ledger_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/chainer"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

var system = domain.Actor{Type: "system", ID: "test"}

func newOrg(t *testing.T, p *db.Pool) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return org
}

func appendN(t *testing.T, p *db.Pool, org ids.OrgID, n int) {
	t.Helper()
	for i := range n {
		err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			body, err := domain.CanonicalBody(map[string]int{"i": i})
			if err != nil {
				return err
			}
			_, err = ledger.Append(ctx, tx, "test.appended", system, body)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func count(t *testing.T, p *db.Pool, org ids.OrgID, table string) int {
	t.Helper()
	var n int
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		q := "SELECT count(*) FROM pc.ledger_entries"
		if table == "chain" {
			q = "SELECT count(*) FROM pc.ledger_chain"
		}
		return tx.QueryRow(ctx, q).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHR110_EntriesAreChainedAfterTheBusinessTransaction(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p)
	appendN(t, p, org, 3)
	if c := count(t, p, org, "chain"); c != 0 {
		t.Fatalf("entries were chained inside the business transaction (%d links)", c)
	}
	chainEventually(t, p, org, 3, 2)
	head, err := ledger.Verify(context.Background(), p, org)
	if err != nil || head.Seq != 3 {
		t.Fatalf("verify = %+v, %v", head, err)
	}
}

func TestIntRollbackLeavesNoGap(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p)
	ctx := context.Background()
	appendN(t, p, org, 1)
	boom := errors.New("rollback")
	_ = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		body, _ := domain.CanonicalBody(map[string]string{"x": "rolled back"})
		if _, err := ledger.Append(ctx, tx, "test.rolled_back", system, body); err != nil {
			return err
		}
		return boom
	})
	appendN(t, p, org, 1)
	chainEventually(t, p, org, 2, 10)
	head, err := ledger.Verify(ctx, p, org)
	if err != nil || head.Seq != 2 {
		t.Fatalf("verify = %+v, %v; want seq 2 with no gap", head, err)
	}
}

func TestIntInFlightTransactionsAreDeferred(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p)
	ctx := context.Background()
	inserted, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			body, _ := domain.CanonicalBody(map[string]string{"x": "slow"})
			if _, err := ledger.Append(ctx, tx, "test.slow", system, body); err != nil {
				return err
			}
			close(inserted)
			<-release
			return nil
		})
	}()
	<-inserted
	appendN(t, p, org, 1) // a later transaction that commits first
	n, err := ledger.ChainAll(ctx, p, org, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("chained %d entries while an older transaction was still open; want 0", n)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	chainEventually(t, p, org, 2, 10)
	if head, err := ledger.Verify(ctx, p, org); err != nil || head.Seq != 2 {
		t.Fatalf("verify = %+v, %v", head, err)
	}
}

func TestIntConcurrentAppendsAndChainers(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var writers sync.WaitGroup
	for range 8 {
		writers.Go(func() { appendN(t, p, org, 25) })
	}
	var chainers sync.WaitGroup
	for range 3 {
		chainers.Go(func() {
			for ctx.Err() == nil {
				if _, err := ledger.ChainOrg(ctx, p, org, 7); err != nil && ctx.Err() == nil {
					t.Errorf("chain: %v", err)
					return
				}
			}
		})
	}
	writers.Wait()
	cancel()
	chainers.Wait()
	chainEventually(t, p, org, 200, 50)
	head, err := ledger.Verify(context.Background(), p, org)
	if err != nil || head.Seq != 200 {
		t.Fatalf("verify = %+v, %v; want 200 contiguous entries", head, err)
	}
	if e, c := count(t, p, org, "entries"), count(t, p, org, "chain"); e != 200 || c != 200 {
		t.Fatalf("entries=%d links=%d, want 200 each (every entry chained exactly once)", e, c)
	}
}

func TestT029_DatabaseTamperingIsDetected(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	for name, tamper := range map[string]string{
		"edit body":   "UPDATE pc.ledger_entries SET body = '{\"i\":99}' WHERE org_id = $1 AND id = (SELECT entry_id FROM pc.ledger_chain WHERE org_id = $1 AND seq = 2)",
		"edit actor":  "UPDATE pc.ledger_entries SET actor_id = 'someone-else' WHERE org_id = $1 AND id = (SELECT entry_id FROM pc.ledger_chain WHERE org_id = $1 AND seq = 1)",
		"delete link": "DELETE FROM pc.ledger_chain WHERE org_id = $1 AND seq = 2",
		"edit head":   "UPDATE pc.ledger_heads SET seq = seq - 1 WHERE org_id = $1",
	} {
		t.Run(name, func(t *testing.T) {
			org := newOrg(t, p)
			appendN(t, p, org, 3)
			chainEventually(t, p, org, 3, 10)
			d.AdminExec(t, tamper, org) // a superuser/insider rewrites history
			if _, err := ledger.Verify(context.Background(), p, org); !errors.Is(err, domain.ErrChainBroken) {
				t.Fatalf("tampering not detected: %v", err)
			}
		})
	}
}

func TestHR055_EvidenceIsAppendOnlyForApp(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p)
	appendN(t, p, org, 1)
	chainEventually(t, p, org, 1, 10)
	for _, stmt := range []string{
		"UPDATE pc.ledger_entries SET kind = 'test.changed'",
		"DELETE FROM pc.ledger_entries",
		"UPDATE pc.ledger_chain SET entry_hash = prev_hash",
		"DELETE FROM pc.ledger_chain",
		"DELETE FROM pc.ledger_heads",
		"TRUNCATE pc.ledger_entries",
	} {
		err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("%q as pc_app: err = %v, want permission denied", stmt, err)
		}
	}
}

func TestIntAuditRecordIsChainedEvidence(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p)
	ctx := context.Background()
	err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "key.created", Actor: domain.Actor{Type: "system", ID: "keystore"}, Outcome: audit.Success,
			Object: &audit.Object{Type: "signing_key", ID: "permits-abc"}, Details: map[string]string{"purpose": "permits"},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var kind string
	var body []byte
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT kind, body FROM pc.ledger_entries").Scan(&kind, &body)
	})
	if err != nil || kind != "audit.key.created" ||
		string(body) != `{"details":{"purpose":"permits"},"name":"key.created","object":{"id":"permits-abc","type":"signing_key"},"outcome":"success"}` {
		t.Fatalf("kind=%q body=%s err=%v", kind, body, err)
	}
	// Another org cannot see it.
	other := newOrg(t, p)
	if n := count(t, p, other, "entries"); n != 0 {
		t.Fatalf("org %s sees %d foreign entries", other, n)
	}
}

func TestIntChainerJobsChainEveryOrg(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newOrg(t, p), newOrg(t, p)
	appendN(t, p, a, 3)
	appendN(t, p, b, 2)
	reg := jobs.NewRegistry()
	if err := chainer.Register(reg, p); err != nil {
		t.Fatal(err)
	}
	c, err := jobs.NewClient(p, reg, jobs.Config{
		Queues: map[string]int{river.QueueDefault: 4}, PeriodicJobs: chainer.PeriodicJobs(), Logger: pclog.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.Stop(sctx)
	})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if count(t, p, a, "chain") == 3 && count(t, p, b, "chain") == 2 {
			for _, org := range []ids.OrgID{a, b} {
				if _, err := ledger.Verify(ctx, p, org); err != nil {
					t.Fatal(err)
				}
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("chainer jobs did not chain both orgs within 30s (a=%d b=%d)", count(t, p, a, "chain"), count(t, p, b, "chain"))
}

// chainEventually chains org until want links exist. The chainer links only
// entries below the cluster-wide snapshot xmin, so open transactions in other
// databases (parallel test packages) can defer chaining; wait for the
// condition instead of assuming one pass suffices (ADR-0009).
func chainEventually(t *testing.T, p *db.Pool, org ids.OrgID, want, batch int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := ledger.ChainAll(context.Background(), p, org, batch); err != nil {
			t.Fatal(err)
		}
		got := count(t, p, org, "chain")
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d entries chained within 30s", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
