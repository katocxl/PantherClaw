// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// devOwnerIssuer is the issuer of the seeded owner; no provider signs for
// it, so nobody can sign in as that user.
const devOwnerIssuer = "https://dev-seed.pantherclaw.invalid"

// seedWorkload adds a ready-to-use PAP/1 workload to a seeded org, in tx:
// a team, an environment, an owner, a CI agent, an admitted instance of a
// new key (enrolled with a consumed enrollment token, as an owner would)
// and a 24-hour run bound to it. It returns the key file to write.
// DEVELOPMENT ONLY.
func seedWorkload(ctx context.Context, tx db.TenantTx, org ids.OrgID, server string) (workloadclient.KeyFile, error) {
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		return kf, err
	}
	team, env, owner := ids.NewV7(), ids.NewV7(), ids.NewV7()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'dev', 'Development')", []any{org, team}},
		{
			"INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Development', 'DEVELOPMENT')",
			[]any{org, env, team},
		},
		{
			"INSERT INTO pc.users (org_id, id, issuer, subject, display_name) VALUES ($1, $2, $3, 'dev-owner', 'Dev owner')",
			[]any{org, owner, devOwnerIssuer},
		},
	} {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			return kf, fmt.Errorf("dev seed: workload: %w", err)
		}
	}
	q := dbq.New(tx)
	ci := string(adomain.ContextCI)
	a, err := q.InsertAgent(ctx, dbq.InsertAgentParams{
		OrgID: org, ID: ids.NewV7(), Name: "dev-refunder", Purpose: "development refunds", TeamID: &team, EnvironmentID: &env,
		OwnerUserID: &owner, ExecutionContext: &ci, CreatedBy: "dev-seed",
	})
	if err != nil {
		return kf, fmt.Errorf("dev seed: agent: %w", err)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return kf, err
	}
	hash := sha256.Sum256(secret[:])
	if _, err := q.InsertEnrollmentToken(ctx, dbq.InsertEnrollmentTokenParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, EnvironmentID: env, TokenHash: hash[:], CreatedBy: "dev-seed", TtlMinutes: 15,
	}); err != nil {
		return kf, err
	}
	et, err := q.ConsumeEnrollmentToken(ctx, org, hash[:])
	if err != nil {
		return kf, err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return kf, err
	}
	in, err := q.InsertInstance(ctx, dbq.InsertInstanceParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Jkt: jws.Thumbprint(pub), PublicJwk: jwk,
		EnrolledVia: "enrollment_token", EnrollmentTokenID: &et.ID,
	})
	if err != nil {
		return kf, err
	}
	by := "dev-seed"
	if _, err := q.AdmitInstance(ctx, &by, org, in.ID); err != nil {
		return kf, err
	}
	if err := agents.MarkVerified(ctx, q, org, a.ID, adomain.System); err != nil {
		return kf, err
	}
	chain, err := json.Marshal([]map[string]string{{"kind": "user", "id": owner.String()}})
	if err != nil {
		return kf, err
	}
	run, err := q.InsertRun(ctx, dbq.InsertRunParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, InstanceID: &in.ID, EnvironmentID: env, LauncherUserID: &owner,
		PrincipalUserID: &owner, PrincipalSource: "launcher", ActorChain: chain, TaskRef: "dev seed", TtlMinutes: 24 * 60,
	})
	if err != nil {
		return kf, err
	}
	kf.Identifier = pap.Instance{Org: org, Agent: a.ID, Instance: in.ID}.String()
	kf.Server, kf.RunID = server, run.ID.String()
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "dev.workload_seeded", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "instance", ID: in.ID.String()},
		Details: map[string]string{"agent_id": a.ID.String(), "run_id": run.ID.String()},
	})
	return kf, err
}
