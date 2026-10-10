// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR079_TheDecisionReceiptRecordsTheDestinationClass: the decision
// receipt names the connection and its destination class, from the
// connection's record.
func TestHR079_TheDecisionReceiptRecordsTheDestinationClass(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	run := s.Run(g.ID, s.Alice)
	gw, err := ids.ParseUUID(s.Gateway.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn := pipeline.Connection{
		ID: ids.NewV7(), Gateway: gw, Kind: "http", Package: "pc.mock-payments", State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, DestinationClass: "internal", Modes: map[string]string{},
	}
	s.W.PutConnection(conn)
	res := s.Authorize(throughConnection(t, s, run, conn.ID, pipelinetest.Refund("ch_1", "30.00")))
	if !res.Decision.Permits() {
		t.Fatalf("decision %s", res.Decision)
	}
	var receipt struct {
		Pap struct {
			Connection       string `json:"connection"`
			DestinationClass string `json:"destination_class"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(res.Receipt), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Pap.Connection != conn.ID.String() || receipt.Pap.DestinationClass != "internal" {
		t.Fatalf("receipt %+v", receipt.Pap)
	}
}
