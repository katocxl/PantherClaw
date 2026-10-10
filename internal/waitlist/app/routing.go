// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Notifier enqueues a notification in the caller's transaction
// (notifications/app.Service), so a rolled-back routing sends nothing.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m notifapp.Message) (notifapp.Enqueued, error)
}

// RouteInterval is how often new entries are routed.
const RouteInterval = 15 * time.Second

const (
	// routeBatch caps the entries one run routes per org.
	routeBatch = 100
	// candidateScan caps the people one routing step checks.
	candidateScan = 200
)

// Router routes new waitlist entries to their eligible deciders (HR-173,
// decision 8): the nearest ones by scope get a personal notice, channels
// subscribed to the type get it too, and each recipient is recorded in
// waitlist_routes. An entry no one may decide is marked
// NO_ELIGIBLE_DECIDER, and for a hold or a restoration the org's admins are
// told; the entry still ends as its kind says at its deadline (F635).
type Router struct {
	Pool   *db.Pool
	Notify Notifier
}

// RouteOrg routes the org's entries that were not routed yet, each in its
// own transaction, and returns how many it routed.
func (r *Router) RouteOrg(ctx context.Context, org ids.OrgID) (int, error) {
	var due []ids.UUID
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		due, err = dbq.New(tx).UnroutedEntries(ctx, org, routeBatch)
		return err
	}, db.ReadOnly())
	if err != nil {
		return 0, err
	}
	for i, id := range due {
		if err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error { return r.route(ctx, tx, org, id) }); err != nil {
			return i, err
		}
	}
	return len(due), nil
}

func (r *Router) route(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) error {
	q := dbq.New(tx)
	e, err := q.EntryForRouting(ctx, org, id)
	if db.IsNoRows(err) {
		return nil // decided meanwhile
	} else if err != nil {
		return err
	}
	ds, err := deciders(ctx, q, org, e)
	if err != nil {
		return err
	}
	m, approval, err := notice(ctx, q, org, e)
	if err != nil {
		return err
	}
	health, kind := wdomain.HealthOK, "decider"
	near := wdomain.Nearest(ds)
	for _, c := range near {
		m.Personal = append(m.Personal, c.User)
	}
	if len(near) == 0 {
		health, kind = wdomain.HealthNoDecider, "admin"
		m.Personal = nil
		if approval {
			m.Type, m.DedupeKey = "approval.unroutable", "unroutable:"+id.String()
			if m.Personal, err = q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin), string(td.RoleSecurityAdmin)}); err != nil {
				return err
			}
		}
	}
	if len(m.Personal) > 0 || approval {
		enq, err := r.Notify.Enqueue(ctx, tx, m)
		if err != nil {
			return err
		}
		if err := recordRoutes(ctx, q, org, id, 0, kind, m.Personal, enq.Channels); err != nil {
			return err
		}
	}
	next := wdomain.NextStep(e.CreatedAt, e.DeadlineAt, 0)
	if _, err := q.SetEntryRouting(ctx, dbq.SetEntryRoutingParams{Health: health, Step: 0, NextStepAt: &next, OrgID: org, ID: id}); err != nil {
		return err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "waitlist.routed", Actor: pgwaitlist.System, Outcome: audit.Success, ReasonCode: health,
		Object:  &audit.Object{Type: "waitlist_entry", ID: id.String()},
		Details: map[string]string{"kind": e.Kind, "step": "0", "deciders": strconv.Itoa(len(near))},
	})
	return err
}

// notice is the entry's first notice: approval.requested for a hold or a
// restoration (ids, the operation and the deadline only), else
// waitlist.entry_created.
func notice(ctx context.Context, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow) (notifapp.Message, bool, error) {
	m := notifapp.Message{
		Org: org, Subject: &notifapp.Subject{Type: "waitlist_entry", ID: e.ID}, DedupeKey: "route:" + e.ID.String() + ":0",
	}
	deadline := e.DeadlineAt.UTC().Format(time.RFC3339)
	if e.Kind != wdomain.KindActionHold && e.Kind != wdomain.KindRestoration {
		m.Type, m.Params = "waitlist.entry_created", map[string]string{"kind": e.Kind, "deadline": deadline}
		return m, false, nil
	}
	req, err := q.GetApprovalRequest(ctx, org, e.SubjectID)
	if err != nil {
		return m, true, err
	}
	m.Type, m.Params = "approval.requested", map[string]string{
		"operation": req.Operation, "agent": req.AgentID.String(), "deadline": deadline, "request": req.ID.String(),
	}
	return m, true, nil
}

func recordRoutes(ctx context.Context, q *dbq.Queries, org ids.OrgID, entry ids.UUID, step int16, kind string, users, channels []ids.UUID) error {
	for _, u := range users {
		if err := q.InsertWaitlistRoute(ctx, dbq.InsertWaitlistRouteParams{
			OrgID: org, ID: ids.NewV7(), EntryID: entry, Step: step, Kind: kind, UserID: &u,
		}); err != nil {
			return err
		}
	}
	for _, c := range channels {
		if err := q.InsertWaitlistRoute(ctx, dbq.InsertWaitlistRouteParams{
			OrgID: org, ID: ids.NewV7(), EntryID: entry, Step: step, Kind: "channel", ChannelID: &c,
		}); err != nil {
			return err
		}
	}
	return nil
}

// deciders returns an entry's eligible deciders, nearest binding first
// (HR-173): the enabled people holding a deciding role where the agent
// lives, kept only if they may respond now. Holds and restorations follow
// the approval rules (a step-up's named person is always one); the other
// kinds need the kind's permission and exclude the requester.
func deciders(ctx context.Context, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow) ([]wdomain.Candidate, error) {
	p := dbq.DeciderCandidatesParams{
		OrgID: org, BusinessUnitID: e.BusinessUnitID, TeamID: e.TeamID, EnvironmentID: e.EnvironmentID, Lim: candidateScan,
	}
	if e.Kind != wdomain.KindActionHold && e.Kind != wdomain.KindRestoration {
		perm, ok := wdomain.DeciderPermission(e.Kind)
		if !ok {
			return nil, nil
		}
		p.Roles = rolesWith(perm)
		cs, err := candidates(ctx, q, p, nil)
		return slices.DeleteFunc(cs, func(c wdomain.Candidate) bool {
			return e.RequestedBy != nil && *e.RequestedBy == td.PrincipalRef{Kind: td.KindUser, ID: c.User}.String()
		}), err
	}
	el, err := pgapprovals.LoadEligibility(ctx, q, org, e.SubjectID, nil)
	if err != nil {
		return nil, err
	}
	var named []ids.UUID
	for _, r := range el.Requirements {
		switch r.Kind {
		case apdomain.KindApproval:
			p.Roles = append(p.Roles, r.Role)
		case apdomain.KindRestore:
			p.Roles = append(p.Roles, rolesWith(td.PermAgentRestore)...)
		case apdomain.KindStepUp:
			if u, err := apdomain.StepUpUser(r, el.Context.Run); err == nil {
				named = append(named, u)
			}
		}
	}
	cs, err := candidates(ctx, q, p, named)
	if err != nil || len(cs) == 0 {
		return nil, err
	}
	users := make([]ids.UUID, len(cs))
	for i, c := range cs {
		users[i] = c.User
	}
	if el, err = pgapprovals.LoadEligibility(ctx, q, org, e.SubjectID, users); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(cs, func(c wdomain.Candidate) bool {
		return !slices.ContainsFunc(el.Requirements, func(r apdomain.Requirement) bool {
			ok, _ := apdomain.MayRespond(r, el.People[c.User], el.Context)
			return ok
		})
	}), nil
}

// candidates are the people holding p.Roles where the agent lives, and the
// named people at the nearest rank, sorted by rank.
func candidates(ctx context.Context, q *dbq.Queries, p dbq.DeciderCandidatesParams, named []ids.UUID) ([]wdomain.Candidate, error) {
	var out []wdomain.Candidate
	for _, u := range named {
		out = append(out, wdomain.Candidate{User: u, Rank: wdomain.RankNear})
	}
	if len(p.Roles) > 0 {
		rows, err := q.DeciderCandidates(ctx, p)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if !slices.ContainsFunc(out, func(c wdomain.Candidate) bool { return c.User == r.UserID }) {
				out = append(out, wdomain.Candidate{User: r.UserID, Rank: int(r.Rank)})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b wdomain.Candidate) int { return a.Rank - b.Rank })
	return out, nil
}

// rolesWith lists the default roles holding p.
func rolesWith(p td.Permission) []string {
	var out []string
	for _, r := range td.Roles() {
		if r.Has(p) {
			out = append(out, string(r.Name))
		}
	}
	return out
}

// RouteOrgArgs asks for one org's new entries to be routed. Job args carry
// ids only (HR-056).
type RouteOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (RouteOrgArgs) Kind() string { return "waitlist.route_org" }

// InsertOpts keeps one queued job per org.
func (RouteOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type routeOrgWorker struct {
	river.WorkerDefaults[RouteOrgArgs]
	router *Router
	log    *slog.Logger
}

func (w *routeOrgWorker) Work(ctx context.Context, job *river.Job[RouteOrgArgs]) error {
	n, err := w.router.RouteOrg(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "waitlist.routed", slog.String("org", job.Args.Org.String()), slog.Int("entries", n))
	}
	return err
}

// RouteDispatchArgs fans routing out to every active org.
type RouteDispatchArgs struct{}

// Kind implements river.JobArgs.
func (RouteDispatchArgs) Kind() string { return "waitlist.route_dispatch" }

type routeDispatchWorker struct {
	river.WorkerDefaults[RouteDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *routeDispatchWorker) Work(ctx context.Context, _ *river.Job[RouteDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("waitlist routing: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: RouteOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterRouting adds the routing workers to reg.
func RegisterRouting(reg *jobs.Registry, router *Router, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[RouteOrgArgs](reg, &routeOrgWorker{router: router, log: log}); err != nil {
		return err
	}
	return jobs.Register[RouteDispatchArgs](reg, &routeDispatchWorker{pool: router.Pool})
}

// RoutingPeriodicJobs returns the routing schedule.
func RoutingPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(RouteInterval),
			func() (river.JobArgs, *river.InsertOpts) { return RouteDispatchArgs{}, nil }, nil),
	}
}
