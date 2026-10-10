// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TB is what a scenario needs from a test: *testing.T or *rapid.T.
type TB interface {
	Helper()
	Fatal(args ...any)
}

// Scenario is one org with the mock-payments package (optionally edited),
// one verified agent with one instance, alice, a gateway and an Authority
// that finalizes into the world.
type Scenario struct {
	TB        TB
	W         *World
	Authority *finalize.Authority
	Gateway   finalize.Gateway
	Mapper    *mapping.Mapper
	Org       ids.OrgID
	Agent     ids.UUID
	Instance  ids.UUID
	Env       ids.UUID
	Team      ids.UUID
	Alice     gdomain.Principal
	// Connection is the enforce-mode HTTP connection to the package that
	// Gateway serves and Request goes through (PAP-1 §6).
	Connection ids.UUID
}

// Start is the scenarios' database time: a Monday noon.
var Start = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// TestOrg is the scenarios' org.
var TestOrg = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")

// RootBounds lets refunds of at most 100 USD on any charge, and reads of
// any refund.
const RootBounds = `{
  "operations": ["payments.refund.create", "payments.refund.get"],
  "targets": {"payments.charge": {"prefixes": ["ch_"]}, "payments.refund": {"prefixes": ["re_"]}},
  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}
}`

// PackagePath returns the path of the reference package.
func PackagePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "packages", "mock-payments", "package.yaml")
}

// NewScenario builds a scenario; edit, when set, changes the package text.
func NewScenario(tb TB, edit func(string) string) *Scenario {
	tb.Helper()
	raw, err := os.ReadFile(PackagePath())
	if err != nil {
		tb.Fatal(err)
	}
	text := string(raw)
	if edit != nil {
		text = edit(text)
	}
	pkg, err := manifest.Decode([]byte(text))
	if err != nil {
		tb.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		tb.Fatal(err)
	}
	s := &Scenario{
		TB: tb, W: New(TestOrg, pkg, Start), Mapper: m, Org: TestOrg,
		Agent: ids.NewV7(), Instance: ids.NewV7(), Env: ids.NewV7(), Team: ids.NewV7(),
		Alice: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: ids.NewV7()},
	}
	gw := ids.NewV7()
	s.Gateway, s.Connection = finalize.Gateway{ID: gw.String(), Org: TestOrg}, ids.NewV7()
	s.W.PutConnection(pipeline.Connection{
		ID: s.Connection, Gateway: gw, Kind: "http", Package: pkg.Name, State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	s.Authority = &finalize.Authority{Pipeline: &pipeline.Pipeline{Reader: s.W}, Store: s.W, Receipts: FakeSigner{}, Permits: FakeSigner{}}
	s.W.AddAgent(s.Agent, pipeline.Agent{State: "VERIFIED", TeamID: s.Team, BusinessUnitID: ids.NewV7()})
	for _, ch := range []string{"ch_1", "ch_2", "ch_3"} {
		s.Refundable(ch)
	}
	return s
}

// Refundable records a fresh "refundable" fact about a charge.
func (s *Scenario) Refundable(charge string) {
	s.W.PutFact(fdomain.Fact{
		Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: charge,
		Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: true}, ObservedAt: s.W.Cont.Now.Add(-time.Minute), ProviderID: ids.NewV7(),
	})
}

// Grant stores a root grant for the agent, acting for p.
func (s *Scenario) Grant(bounds string, p gdomain.Principal) gdomain.Grant {
	s.TB.Helper()
	b, err := gdomain.DecodeBounds([]byte(bounds))
	if err != nil {
		s.TB.Fatal(err)
	}
	g := gdomain.Grant{
		ID: gdomain.NewGrantID(), Org: s.Org, Revision: 1, State: gdomain.StateActive,
		AgentID: s.Agent, Principal: p, EnvironmentID: s.Env, NotBefore: Start.Add(-time.Hour), ExpiresAt: Start.Add(48 * time.Hour),
		Bounds: b, Delegation: gdomain.Delegation{Depth: 2, MaxChildren: 10}, Grantor: s.Alice, Basis: "test",
	}
	s.W.Grants.Put(g)
	return g
}

// Run starts an active run of the agent's instance under grant g.
func (s *Scenario) Run(g gdomain.GrantID, p gdomain.Principal) ids.UUID {
	id := ids.NewV7()
	s.W.AddRun(id, pipeline.Run{AgentID: s.Agent, InstanceID: s.Instance, Launcher: p, Principal: p, EnvironmentID: s.Env, GrantID: g, Active: true})
	return id
}

// Request maps an MCP tool call into a request in run with action id act.
func (s *Scenario) Request(run, act ids.UUID, tool, input string) pipeline.Request {
	s.TB.Helper()
	p, err := s.Mapper.MCP(context.Background(), mapping.Context{
		Org: s.Org.String(), Env: s.Env.String(), RunID: run.String(), ActionID: act.String(), AgentInstance: s.Instance.String(),
		Connection: s.Connection.String(),
	}, tool, jsontext.Value(input))
	if err != nil {
		s.TB.Fatal(err)
	}
	return pipeline.Request{
		Org: s.Org, Action: p, Identity: pipeline.Identity{InstanceID: s.Instance, AgentID: s.Agent, AttestationLevel: 1}, Gateway: s.Gateway.ID,
	}
}

// Authorize decides a request through the Authority.
func (s *Scenario) Authorize(req pipeline.Request) finalize.Result {
	s.TB.Helper()
	res, err := s.Authority.Authorize(context.Background(), s.Gateway, req)
	if err != nil {
		s.TB.Fatal(err)
	}
	return res
}

// Refund is the MCP input of a refund.
func Refund(charge, amount string) string {
	return `{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`
}

// FakeSigner "signs" as header.payload.signature with an unverifiable
// signature, so tests can read the payload.
type FakeSigner struct{}

// Sign implements finalize.Signer.
func (FakeSigner) Sign(typ string, payload []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"`+typ+`"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".test", nil
}

// Payload returns the payload of a FakeSigner JWS.
func Payload(jws string) []byte {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	return b
}
