// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// JanitorInterval is how often expired authentication rows are removed.
const JanitorInterval = 10 * time.Minute

// Cleaned counts the rows one janitor run removed.
type Cleaned struct {
	Replay, DeviceCodes, Sessions int64
}

// CleanOrg removes one org's expired client-assertion jtis (an expired
// assertion can no longer be replayed), device codes closed for a day and
// CLI sessions that ended more than 30 days ago.
func CleanOrg(ctx context.Context, pool *db.Pool, org ids.OrgID) (Cleaned, error) {
	var c Cleaned
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if c.Replay, err = q.DeleteExpiredReplay(ctx, org); err != nil {
			return err
		}
		if c.DeviceCodes, err = q.DeleteOldDeviceCodes(ctx, org); err != nil {
			return err
		}
		c.Sessions, err = q.DeleteOldSessions(ctx, org)
		return err
	})
	return c, err
}

// JanitorOrgArgs asks for one org to be cleaned. Job args carry ids only
// (HR-056).
type JanitorOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (JanitorOrgArgs) Kind() string { return "authn.janitor_org" }

// InsertOpts keeps one queued job per org.
func (JanitorOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type janitorOrgWorker struct {
	river.WorkerDefaults[JanitorOrgArgs]
	pool *db.Pool
	log  *slog.Logger
}

func (w *janitorOrgWorker) Work(ctx context.Context, job *river.Job[JanitorOrgArgs]) error {
	c, err := CleanOrg(ctx, w.pool, job.Args.Org)
	if err == nil && c.Replay+c.DeviceCodes+c.Sessions > 0 {
		w.log.InfoContext(ctx, "authn.janitor", slog.String("org", job.Args.Org.String()), slog.Int64("replay", c.Replay),
			slog.Int64("device_codes", c.DeviceCodes), slog.Int64("sessions", c.Sessions))
	}
	return err
}

// JanitorDispatchArgs fans the janitor out to every active org.
type JanitorDispatchArgs struct{}

// Kind implements river.JobArgs.
func (JanitorDispatchArgs) Kind() string { return "authn.janitor_dispatch" }

type janitorDispatchWorker struct {
	river.WorkerDefaults[JanitorDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *janitorDispatchWorker) Work(ctx context.Context, _ *river.Job[JanitorDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("authn janitor: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: JanitorOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterJanitor adds the janitor workers to reg.
func RegisterJanitor(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[JanitorOrgArgs](reg, &janitorOrgWorker{pool: pool, log: log}); err != nil {
		return err
	}
	return jobs.Register[JanitorDispatchArgs](reg, &janitorDispatchWorker{pool: pool})
}

// JanitorPeriodicJobs returns the janitor schedule.
func JanitorPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JanitorInterval),
			func() (river.JobArgs, *river.InsertOpts) { return JanitorDispatchArgs{}, nil }, nil),
	}
}
