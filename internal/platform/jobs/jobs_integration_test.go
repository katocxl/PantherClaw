// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package jobs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type pingArgs struct {
	Org ids.OrgID `json:"org"`
}

func (pingArgs) Kind() string { return "test.ping" }

type pingWorker struct {
	river.WorkerDefaults[pingArgs]
	pool *db.Pool
	done chan string
}

// Work opens a tenant transaction for the org named in the arguments, as
// every tenant-touching job must (HR-054).
func (w pingWorker) Work(ctx context.Context, job *river.Job[pingArgs]) error {
	return w.pool.InTenantTx(ctx, job.Args.Org, func(ctx context.Context, tx db.TenantTx) error {
		var name string
		if err := tx.QueryRow(ctx, "SELECT name FROM pc.orgs WHERE id = $1", tx.OrgID()).Scan(&name); err != nil {
			return err
		}
		w.done <- name
		return nil
	})
}

func newOrg(t *testing.T, p *db.Pool, name string) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, name)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return org
}

func TestIntJobsAreATransactionalOutbox(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := newOrg(t, p, "acme")
	ctx := context.Background()

	done := make(chan string, 4)
	reg := jobs.NewRegistry()
	if err := jobs.Register[pingArgs](reg, pingWorker{pool: p, done: done}); err != nil {
		t.Fatal(err)
	}
	inserter, err := jobs.NewClient(p, nil, jobs.Config{Logger: pclog.Discard()})
	if err != nil {
		t.Fatal(err)
	}

	// A rolled-back business transaction leaves no job behind.
	errRollback := errors.New("rollback")
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if err := jobs.InsertTx(ctx, inserter, tx, pingArgs{Org: org}, nil); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
	var queued int
	if err := p.Pgx().QueryRow(ctx, "SELECT count(*) FROM pc.river_job").Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("rolled-back transaction left %d jobs", queued)
	}

	// A committed one is worked by a client running as pc_app.
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return jobs.InsertTx(ctx, inserter, tx, pingArgs{Org: org}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := jobs.NewClient(p, reg, jobs.Config{Queues: map[string]int{river.QueueDefault: 2}, Logger: pclog.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = worker.Stop(sctx)
	})
	select {
	case name := <-done:
		if name != "acme" {
			t.Fatalf("worker saw org %q", name)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("job was not worked within 30s")
	}
}

func TestIntRiverTablesAreNotTruncatableByApp(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	_, err := p.Pgx().Exec(context.Background(), "TRUNCATE pc.river_job")
	if !db.IsPermissionDenied(err) {
		t.Fatalf("TRUNCATE river_job as pc_app: %v, want permission denied (HR-055)", err)
	}
}
