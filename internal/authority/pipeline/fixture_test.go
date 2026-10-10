// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"os"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

var (
	org = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")
	now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) // a Monday
)

// fx is one org with the mock-payments package, an agent, a root grant for
// alice and an active run under it.
type fx struct {
	t        *testing.T
	w        *pipelinetest.World
	p        *pipeline.Pipeline
	mapper   *mapping.Mapper
	pkg      *defs.Package
	agent    ids.UUID
	instance ids.UUID
	env      ids.UUID
	team     ids.UUID
	alice    gdomain.Principal
	grant    gdomain.Grant
	run      ids.UUID
	provider ids.UUID
	// gateway serves conn, an enforce-mode HTTP connection to the package
	// that every call goes through (PAP-1 §6).
	gateway, conn ids.UUID
}

const grantBounds = `{
  "operations": ["payments.refund.create", "payments.refund.get"],
  "targets": {"payments.charge": {"prefixes": ["ch_"]}, "payments.refund": {"ids": ["re_1", "re_2"]}},
  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}
}`

func newFx(t *testing.T) *fx { return newFxWith(t, nil, "") }

// newFxWith edits the reference package before loading it: edit changes
// the definitions, and mcpParams (when set) replaces the MCP refund
// mapping's last parameter lines.
func newFxWith(t *testing.T, edit func([]byte) []byte, mcpParams string) *fx {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		raw = edit(raw)
	}
	if mcpParams != "" {
		// The MCP refund mapping is the refund definition's last mapping,
		// right before its dispatch template.
		mcp := []byte("            reason: input.reason\n    dispatch:")
		if !bytes.Contains(raw, mcp) {
			t.Fatal("the MCP refund mapping moved; update the fixture")
		}
		raw = bytes.Replace(raw, mcp, []byte(mcpParams+"\n    dispatch:"), 1)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{
		t: t, w: pipelinetest.New(org, pkg, now), mapper: m, pkg: pkg,
		agent: ids.NewV7(), instance: ids.NewV7(), env: ids.NewV7(), team: ids.NewV7(),
		alice: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: ids.NewV7()}, provider: ids.NewV7(),
		gateway: ids.NewV7(), conn: ids.NewV7(),
	}
	f.w.PutConnection(pipeline.Connection{
		ID: f.conn, Gateway: f.gateway, Kind: "http", Package: pkg.Name, State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	f.p = &pipeline.Pipeline{Reader: f.w}
	f.w.AddAgent(f.agent, pipeline.Agent{State: "VERIFIED", TeamID: f.team, BusinessUnitID: ids.NewV7()})
	f.grant = f.newGrant(grantBounds)
	f.w.Grants.Put(f.grant)
	f.run = f.newRun(f.grant.ID)
	f.putFact("ch_1", true, now.Add(-time.Minute))
	return f
}

func (f *fx) newGrant(bounds string) gdomain.Grant {
	f.t.Helper()
	b, err := gdomain.DecodeBounds([]byte(bounds))
	if err != nil {
		f.t.Fatal(err)
	}
	return gdomain.Grant{
		ID: gdomain.NewGrantID(), Org: org, Revision: 1, State: gdomain.StateActive,
		AgentID: f.agent, Principal: f.alice, EnvironmentID: f.env, TaskRef: "refunds",
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour), Bounds: b,
		Delegation: gdomain.Delegation{Depth: 2, MaxChildren: 3}, Grantor: f.alice, Basis: "test",
	}
}

func (f *fx) newRun(grant gdomain.GrantID) ids.UUID {
	id := ids.NewV7()
	f.w.AddRun(id, pipeline.Run{AgentID: f.agent, InstanceID: f.instance, Launcher: f.alice, Principal: f.alice, EnvironmentID: f.env, GrantID: grant, Active: true})
	return id
}

func (f *fx) putFact(charge string, refundable bool, observed time.Time) {
	f.w.PutFact(fdomain.Fact{
		Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: charge,
		Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: refundable}, ObservedAt: observed, RecordedAt: observed, ProviderID: f.provider,
	})
}

// call maps an MCP tool call in run (a fresh action id) and evaluates it.
func (f *fx) call(run ids.UUID, tool, input string) *pipeline.Evaluation {
	f.t.Helper()
	return f.eval(f.parse(run, ids.NewV7(), tool, input))
}

func (f *fx) parse(run, action ids.UUID, tool, input string) pipeline.Request {
	f.t.Helper()
	p, err := f.mapper.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: f.env.String(), RunID: run.String(), ActionID: action.String(), AgentInstance: f.instance.String(),
		Connection: f.conn.String(),
	}, tool, jsontext.Value(input))
	if err != nil {
		f.t.Fatal(err)
	}
	return pipeline.Request{
		Org: org, Action: p, Identity: pipeline.Identity{InstanceID: f.instance, AgentID: f.agent, AttestationLevel: 1}, Gateway: f.gateway.String(),
	}
}

func (f *fx) eval(req pipeline.Request) *pipeline.Evaluation {
	f.t.Helper()
	ev, err := f.p.Evaluate(context.Background(), req)
	if err != nil {
		f.t.Fatal(err)
	}
	return ev
}

func refund(charge, amount string) string {
	return `{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`
}

// expect checks the decision and the decisive reason (F194).
func expect(t *testing.T, ev *pipeline.Evaluation, d adomain.Decision, code string) {
	t.Helper()
	got := ev.Decisive()
	if ev.Decision != d || got.Code != code {
		t.Fatalf("decision %s (%s: %s), want %s (%s)\nchecklist: %+v", ev.Decision, got.Code, got.Detail, d, code, ev.Checklist)
	}
}

func approvalOver50() pdomain.Rule {
	return pdomain.Rule{
		ID: "approve-over-50", Kind: pdomain.RequireApproval, Summary: "refunds over 50 USD need an approver",
		Operations: []string{"payments.refund.create"}, When: `action.params.amount > money("50.00", "USD")`,
		Reason: "REFUND_OVER_50", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
}

func testEvent() audit.Event { return audit.Event{Name: "test.event", Outcome: audit.Success} }
