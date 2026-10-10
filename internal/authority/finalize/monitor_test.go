// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// monitored is a scenario whose gateway serves one connection in monitor
// mode.
func monitored(t *testing.T) (*pipelinetest.Scenario, ids.UUID, ids.UUID) {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	gw := ids.NewV7()
	s.Gateway.ID = gw.String()
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	run := s.Run(g.ID, s.Alice)
	conn := pipeline.Connection{
		ID: ids.NewV7(), Gateway: gw, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE", AccessMode: "pantherclaw_held",
		DefaultMode: pipeline.ModeMonitor, Modes: map[string]string{},
	}
	s.W.PutConnection(conn)
	return s, run, conn.ID
}

func throughConnection(t *testing.T, s *pipelinetest.Scenario, run, conn ids.UUID, input string) pipeline.Request {
	t.Helper()
	p, err := s.Mapper.MCP(context.Background(), mapping.Context{
		Org: s.Org.String(), Env: s.Env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: s.Instance.String(),
		Connection: conn.String(),
	}, "create_refund", jsontext.Value(input))
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.Request{Org: s.Org, Action: p, Identity: pipeline.Identity{InstanceID: s.Instance, AgentID: s.Agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}}
}

// TestHR184_MonitorModeIssuesAPermitOverAHypotheticalDecision: over the
// grant's limit, monitor mode still returns a permit for the requested
// action, records the decision as hypothetical (monitor: true in the
// receipt) and closes the transaction, so a repeat gets no second permit.
func TestHR184_MonitorModeIssuesAPermitOverAHypotheticalDecision(t *testing.T) {
	s, run, conn := monitored(t)
	req := throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "500.00"))
	res := s.Authorize(req)
	if res.Decision.Permits() || res.Permit == "" || res.Mode != pipeline.ModeMonitor || res.AccessMode != "pantherclaw_held" {
		t.Fatalf("monitor over the grant: %s permit %q mode %s", res.Decision, res.Permit, res.Mode)
	}
	var permit struct {
		Pap struct {
			Act string `json:"act"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(res.Permit), &permit); err != nil || permit.Pap.Act != res.ActionHash {
		t.Fatalf("the monitor permit binds %q, want the requested action %q (%v)", permit.Pap.Act, res.ActionHash, err)
	}
	var receipt struct {
		Pap struct {
			Monitor    bool             `json:"monitor"`
			Connection string           `json:"connection"`
			Decision   adomain.Decision `json:"decision"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(res.Receipt), &receipt); err != nil || !receipt.Pap.Monitor ||
		receipt.Pap.Connection != conn.String() || receipt.Pap.Decision != res.Decision {
		t.Fatalf("receipt %+v %v", receipt.Pap, err)
	}
	again := s.Authorize(req)
	if !again.Repeat || again.Permit != "" {
		t.Fatalf("a repeat got a second permit: repeat %v permit %q", again.Repeat, again.Permit)
	}
}

// TestHR184_MonitorModeStopsForTheKillSwitch: with the kill switch on, a
// monitor-mode action is denied and gets no permit.
func TestHR184_MonitorModeStopsForTheKillSwitch(t *testing.T) {
	s, run, conn := monitored(t)
	s.W.Cont.KillSwitch = true
	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "10.00")))
	if res.Decision != adomain.Deny || res.Permit != "" {
		t.Fatalf("kill switch: %s permit %q", res.Decision, res.Permit)
	}
}
