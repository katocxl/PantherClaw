// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// withConnection gives the world's gateway a row and one connection to the
// mock payments API in mode (the default for all its routes).
func (w *world) withConnection(mode string) ids.UUID {
	w.t.Helper()
	gw, conn := ids.NewV7(), ids.NewV7()
	exec(w.t, w.pool, w.org, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, gw)
	exec(w.t, w.pool, w.org, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode,
		default_mode, created_by, updated_by) VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments', 'https://payments.example.test',
		'none', $4, 'test', 'test')`, w.org, conn, gw, mode)
	w.gw = finalize.Gateway{ID: gw.String(), Org: w.org}
	return conn
}

func (w *world) through(conn, run ids.UUID, charge, amount string) pipeline.Request {
	w.t.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: w.org.String(), Env: w.env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: w.instance.String(),
		Connection: conn.String(),
	}, "create_refund", []byte(`{"charge":"`+charge+`","amount":"`+amount+`","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		w.t.Fatal(err)
	}
	return pipeline.Request{Org: w.org, Action: p, Identity: pipeline.Identity{InstanceID: w.instance, AgentID: w.agent, AttestationLevel: 1}}
}

func (w *world) scalar(sql string, args ...any) string {
	w.t.Helper()
	var s string
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&s)
	}); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// TestHR184_MonitorPermitsReserveNothingAndStillMeetContainment: in
// PostgreSQL, monitor-mode actions over a 50 USD budget all get permits,
// reserve nothing, and are recorded as monitor with their connection,
// channel and target; their permits still go through BeginDispatch, which
// the kill switch stops.
func TestHR184_MonitorPermitsReserveNothingAndStillMeetContainment(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.grant("50")
	run := w.run(g.ID, ids.UUID{})
	conn := w.withConnection(pipeline.ModeMonitor)
	ctx := context.Background()

	// Monitor mode reserves nothing, so earlier monitor actions never count
	// against the budget; an amount over the grant's 100 USD per-action
	// maximum is hypothetically refused and still gets a permit.
	var permits []finalize.Result
	for _, amount := range []string{"40.00", "40.00", "150.00"} {
		res := w.authorize(w.through(conn, run, "ch_1", amount))
		if res.Permit == "" || res.Mode != pipeline.ModeMonitor {
			t.Fatalf("monitor action of %s: %s permit %q mode %s (%s)", amount, res.Decision, res.Permit, res.Mode, decisive(res))
		}
		permits = append(permits, res)
	}
	if !permits[1].Decision.Permits() || permits[2].Decision.Permits() {
		t.Fatalf("hypothetical decisions %s and %s", permits[1].Decision, permits[2].Decision)
	}
	if got := w.scalar("SELECT coalesce(sum(reserved), 0)::text || '/' || coalesce(sum(spent), 0)::text FROM pc.budget_accounts"); got != "0/0" &&
		got != "0.00000000/0.00000000" {
		t.Fatalf("monitor mode reserved budget: %s", got)
	}
	if got := w.scalar(`SELECT count(*)::text FROM pc.permits WHERE mode = 'monitor' AND connection_id = $1`, conn); got != "3" {
		t.Fatalf("%s monitor permits recorded, want 3", got)
	}
	if got := w.scalar(`SELECT string_agg(DISTINCT mode || ':' || channel || ':' || target_type || ':' || target_id, ',')
		FROM pc.transactions WHERE connection_id = $1`, conn); got != "monitor:mcp:payments.charge:ch_1" {
		t.Fatalf("transactions record %q", got)
	}
	if err := w.auth.BeginDispatch(ctx, w.gw, permits[0].PermitID, permits[0].Epoch); err != nil {
		t.Fatalf("a monitor permit goes through BeginDispatch: %v", err)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: permits[0].PermitID, Outcome: finalize.Accepted}); err != nil {
		t.Fatalf("record: %v", err)
	}
	exec(t, w.pool, w.org, `UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1, engaged_by = 'test', engaged_at = now(),
		engage_reason = 'test' WHERE org_id = $1`, w.org)
	if err := w.auth.BeginDispatch(ctx, w.gw, permits[2].PermitID, permits[2].Epoch); !errors.Is(err, finalize.ErrKillSwitch) {
		t.Fatalf("the kill switch did not stop a monitor permit: %v", err)
	}
	if res := w.authorize(w.through(conn, run, "ch_1", "10.00")); res.Permit != "" {
		t.Fatalf("a monitor action got a permit with the kill switch on: %s", res.Decision)
	}
}

// TestPAP1_TheAuthorityChecksTheConnectionInPostgres: an action naming a
// connection the gateway does not serve is refused, and an enforced route
// is decided for real.
func TestPAP1_TheAuthorityChecksTheConnectionInPostgres(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	g := w.grant("500")
	run := w.run(g.ID, ids.UUID{})
	conn := w.withConnection(pipeline.ModeEnforce)
	if res := w.authorize(w.through(conn, run, "ch_1", "30.00")); !res.Decision.Permits() || res.Mode != pipeline.ModeEnforce {
		t.Fatalf("enforced route: %s %s (%s)", res.Decision, res.Mode, decisive(res))
	}
	w.gw.ID = ids.NewV7().String()
	if res := w.authorize(w.through(conn, run, "ch_1", "30.00")); res.Permit != "" || decisive(res) != pipeline.ReasonConnectionUnknown {
		t.Fatalf("another gateway's connection: %s (%s)", res.Decision, decisive(res))
	}
}
