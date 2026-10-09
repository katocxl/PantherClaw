// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"maps"
	"path/filepath"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxOpenScanDiscoveries is the cap on open discoveries per org, the same
// as for gateway discoveries (HR-148).
const MaxOpenScanDiscoveries = 200

// ScanFinding is one finding of a local `pclaw scan` (PN-001.1). Its
// attributes are UNTRUSTED observations.
type ScanFinding struct {
	Kind       string
	Key        [32]byte
	Attributes map[string]string
}

// ScanResult counts what a submission did.
type ScanResult struct {
	Created, Counted, Dropped int
}

// scanName is a readable name for a discovered agent; nothing binds to it
// (F034).
func scanName(f ScanFinding) string {
	var s string
	switch f.Kind {
	case "mcp_server":
		s = "MCP server " + f.Attributes["name"]
		if c := f.Attributes["client"]; c != "" {
			s += " (" + c + ")"
		}
	default:
		s = "agent project " + filepath.Base(f.Attributes["path"])
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// SubmitScan records scan findings as DISCOVERED agents, each with a
// discovery and an ADMISSION entry (F015); a finding submitted before is
// only counted. The caller needs agent.manage somewhere in the org. At
// most MaxOpenScanDiscoveries discoveries are open per org; past that,
// findings are dropped and counted. Submitting grants nothing.
func (inv *Inventory) SubmitScan(ctx context.Context, host string, findings []ScanFinding) (ScanResult, error) {
	var res ScanResult
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if !c.CanAnywhere(td.PermAgentManage) {
			return td.ErrPermissionDenied(td.PermAgentManage)
		}
		if err := q.LockDiscoveries(ctx, c.Org.String()); err != nil {
			return err
		}
		open, err := q.CountOpenDiscoveries(ctx, c.Org)
		if err != nil {
			return err
		}
		by := actor(c)
		for _, f := range findings {
			observed := maps.Clone(f.Attributes)
			if observed == nil {
				observed = map[string]string{}
			}
			observed["kind"], observed["submitted_by"] = f.Kind, string(by)
			if host != "" {
				observed["host"] = host
			}
			obs, err := json.Marshal(observed)
			if err != nil {
				return err
			}
			n, err := q.TouchScanDiscovery(ctx, obs, c.Org, f.Key[:])
			if err != nil {
				return err
			}
			if n > 0 {
				res.Counted++
				continue
			}
			if open >= MaxOpenScanDiscoveries {
				res.Dropped++
				continue
			}
			if err := insertScanFinding(ctx, q, c, f, obs, observed); err != nil {
				return err
			}
			open++
			res.Created++
		}
		return record(ctx, tx, c, "agents.scan_submitted", ids.UUID{}, map[string]string{
			"created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted), "dropped": strconv.Itoa(res.Dropped),
		})
	})
	if err != nil {
		return ScanResult{}, err
	}
	return res, nil
}

func insertScanFinding(ctx context.Context, q *dbq.Queries, c tenancy.Caller, f ScanFinding, obs []byte, observed map[string]string) error {
	a, err := q.InsertDiscoveredAgent(ctx, dbq.InsertDiscoveredAgentParams{
		OrgID: c.Org, ID: ids.NewV7(), Name: scanName(f), CreatedBy: c.Principal.String(),
	})
	if err != nil {
		return err
	}
	d, err := q.InsertScanDiscovery(ctx, dbq.InsertScanDiscoveryParams{OrgID: c.Org, ID: ids.NewV7(), AgentID: a.ID, ScanKey: f.Key[:], Observed: obs})
	if err != nil {
		return err
	}
	ev, err := json.Marshal(map[string]map[string]string{
		"trusted":   {"source": "scan", "discovery_id": d.ID.String(), "submitted_by": c.Principal.String()},
		"untrusted": observed,
	})
	if err != nil {
		return err
	}
	if _, err := q.InsertAgentAdmissionEntry(ctx, dbq.InsertAgentAdmissionEntryParams{
		OrgID: c.Org, ID: ids.NewV7(), AgentID: a.ID, Evidence: ev,
	}); err != nil {
		return err
	}
	return RecordChange(ctx, q, c.Org, a.ID, domain.Change{
		Kind: domain.ChangeDiscovered, Actor: actor(c), Details: map[string]string{"discovery_id": d.ID.String(), "source": "scan"},
	})
}
