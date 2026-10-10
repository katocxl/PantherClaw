// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

const (
	// ExpireInterval is how often orgs with expired leases or closed
	// windows are found.
	ExpireInterval   = 5 * time.Second
	maxOrgsPerExpire = 1000
)

// ExpireOrgArgs asks for one org's expired leases and windows to be ended.
type ExpireOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ExpireOrgArgs) Kind() string { return "transactions.verifications_expire_org" }

// InsertOpts makes expiry jobs unique per org while queued or running.
func (ExpireOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// ExpireOrgWorker ends one org's expired leases and windows.
type ExpireOrgWorker struct {
	river.WorkerDefaults[ExpireOrgArgs]
	Service *Service
}

// Work implements river.Worker.
func (w *ExpireOrgWorker) Work(ctx context.Context, job *river.Job[ExpireOrgArgs]) error {
	_, err := w.Service.Expire(ctx, job.Args.Org)
	return err
}

// ExpireDispatchArgs asks for expiry jobs for every org with due tasks.
type ExpireDispatchArgs struct{}

// Kind implements river.JobArgs.
func (ExpireDispatchArgs) Kind() string { return "transactions.verifications_expire_dispatch" }

// ExpireDispatchWorker finds orgs via the audited lister (HR-054).
type ExpireDispatchWorker struct {
	river.WorkerDefaults[ExpireDispatchArgs]
	Pool *db.Pool
}

// Work implements river.Worker.
func (w *ExpireDispatchWorker) Work(ctx context.Context, _ *river.Job[ExpireDispatchArgs]) error {
	refs, err := w.Pool.CrossOrgList(ctx, db.ListVerificationsDue, maxOrgsPerExpire)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("verifications: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: ExpireOrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("verifications: enqueue: %w", err)
	}
	return nil
}

// Register adds the verification workers to reg.
func Register(reg *jobs.Registry, pool *db.Pool, s *Service) error {
	if err := jobs.Register[ExpireOrgArgs](reg, &ExpireOrgWorker{Service: s}); err != nil {
		return err
	}
	return jobs.Register[ExpireDispatchArgs](reg, &ExpireDispatchWorker{Pool: pool})
}

// PeriodicJobs returns the dispatcher schedule for the worker client.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(
			river.PeriodicInterval(ExpireInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ExpireDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true},
		),
	}
}
