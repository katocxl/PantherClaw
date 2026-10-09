// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// recordM4 records the last request of each M4 service.
type recordM4 struct {
	pantherclawv1connect.UnimplementedGrantServiceHandler
	pantherclawv1connect.UnimplementedGuardrailServiceHandler
	pantherclawv1connect.UnimplementedFactServiceHandler
	pantherclawv1connect.UnimplementedPackageServiceHandler
	pantherclawv1connect.UnimplementedPolicyServiceHandler
	issue    *pantherclawv1.IssueGrantRequest
	revise   *pantherclawv1.ReviseGrantRequest
	grants   *pantherclawv1.ListGrantsRequest
	envelope *pantherclawv1.CreateEnvelopeRequest
	provider *pantherclawv1.RegisterProviderRequest
	facts    *pantherclawv1.PutFactsRequest
	imported *pantherclawv1.ImportPackageRequest
	moved    *pantherclawv1.TransitionPackageRequest
	policy   *pantherclawv1.CreatePolicyVersionRequest
}

func (r *recordM4) IssueGrant(_ context.Context, req *pantherclawv1.IssueGrantRequest) (*pantherclawv1.IssueGrantResponse, error) {
	r.issue = req
	return &pantherclawv1.IssueGrantResponse{Grant: &pantherclawv1.Grant{Id: "g1", Revision: 1}}, nil
}

func (r *recordM4) ReviseGrant(_ context.Context, req *pantherclawv1.ReviseGrantRequest) (*pantherclawv1.ReviseGrantResponse, error) {
	r.revise = req
	return &pantherclawv1.ReviseGrantResponse{Grant: &pantherclawv1.Grant{Id: req.GetId(), Revision: req.GetRevision() + 1}}, nil
}

func (r *recordM4) ListGrants(_ context.Context, req *pantherclawv1.ListGrantsRequest) (*pantherclawv1.ListGrantsResponse, error) {
	r.grants = req
	return &pantherclawv1.ListGrantsResponse{}, nil
}

func (r *recordM4) CreateEnvelope(_ context.Context, req *pantherclawv1.CreateEnvelopeRequest) (*pantherclawv1.CreateEnvelopeResponse, error) {
	r.envelope = req
	return &pantherclawv1.CreateEnvelopeResponse{Envelope: &pantherclawv1.Envelope{Id: "e1", Revision: 1}}, nil
}

func (r *recordM4) RegisterProvider(_ context.Context, req *pantherclawv1.RegisterProviderRequest) (*pantherclawv1.RegisterProviderResponse, error) {
	r.provider = req
	return &pantherclawv1.RegisterProviderResponse{Provider: &pantherclawv1.FactProvider{Id: "p1"}}, nil
}

func (r *recordM4) PutFacts(_ context.Context, req *pantherclawv1.PutFactsRequest) (*pantherclawv1.PutFactsResponse, error) {
	r.facts = req
	return &pantherclawv1.PutFactsResponse{Results: []*pantherclawv1.FactResult{{Accepted: true}}}, nil
}

func (r *recordM4) ImportPackage(_ context.Context, req *pantherclawv1.ImportPackageRequest) (*pantherclawv1.ImportPackageResponse, error) {
	r.imported = req
	return &pantherclawv1.ImportPackageResponse{Package: &pantherclawv1.PackageVersion{Name: req.GetName(), Version: req.GetVersion()}}, nil
}

func (r *recordM4) TransitionPackage(_ context.Context, req *pantherclawv1.TransitionPackageRequest) (*pantherclawv1.TransitionPackageResponse, error) {
	r.moved = req
	return &pantherclawv1.TransitionPackageResponse{Package: &pantherclawv1.PackageVersion{Name: req.GetName(), State: req.GetState()}}, nil
}

func (r *recordM4) CreatePolicyVersion(_ context.Context, req *pantherclawv1.CreatePolicyVersionRequest) (*pantherclawv1.CreatePolicyVersionResponse, error) {
	r.policy = req
	return &pantherclawv1.CreatePolicyVersionResponse{Version: &pantherclawv1.PolicyVersion{Id: "v1", State: "DRAFT"}}, nil
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestM4Commands: the grant, guardrail, fact, package and policy commands
// send what their flags and files say, read documents from files as they
// are, and refuse malformed flags before calling the server.
func TestM4Commands(t *testing.T) {
	r := &recordM4{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterGrantServiceHandler(cs, r)
	pantherclawv1connect.RegisterGuardrailServiceHandler(cs, r)
	pantherclawv1connect.RegisterFactServiceHandler(cs, r)
	pantherclawv1connect.RegisterPackageServiceHandler(cs, r)
	pantherclawv1connect.RegisterPolicyServiceHandler(cs, r)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	dir := t.TempDir()
	bounds := writeTemp(t, dir, "bounds.json", `{"operations": ["payments.refund.create"]}`)
	limits := writeTemp(t, dir, "limits.json", `{"budgets": []}`)

	const agent, user = "0192aaaa-bbbb-7ccc-8ddd-000000000001", "0192aaaa-bbbb-7ccc-8ddd-000000000002"
	code, out, errs := run(t, env, "grant", "issue", agent, "--principal", "user:"+user, "--expires", "48h", "--bounds-file", bounds,
		"--limits-file", limits, "--task", "refunds", "--delegation-depth", "9", "--max-children", "3", "--min-attestation", "1")
	if code != 0 || !strings.Contains(out, `"g1"`) {
		t.Fatalf("grant issue = %d %q %q", code, out, errs)
	}
	is := r.issue
	if is.GetAgentId() != agent || is.GetPrincipal().GetKind() != "user" || is.GetPrincipal().GetId() != user ||
		string(is.GetBounds()) != `{"operations": ["payments.refund.create"]}` || string(is.GetLimits()) != `{"budgets": []}` ||
		len(is.GetRequirements()) != 0 || is.GetDelegation().GetDepth() != 4 || is.GetDelegation().GetMaxChildren() != 3 ||
		is.GetMinAttestationLevel() != 1 || is.GetTaskRef() != "refunds" || is.InstanceId != nil ||
		time.Until(is.GetExpireTime().AsTime()) < 47*time.Hour || time.Until(is.GetExpireTime().AsTime()) > 49*time.Hour {
		t.Fatalf("grant issue sent %v", is)
	}
	for name, args := range map[string][]string{
		"a principal without a kind": {"grant", "issue", agent, "--principal", user, "--expires", "48h", "--bounds-file", bounds},
		"an agent as principal":      {"grant", "issue", agent, "--principal", "instance:" + user, "--expires", "48h", "--bounds-file", bounds},
		"no expiry":                  {"grant", "issue", agent, "--principal", "user:" + user, "--bounds-file", bounds},
		"no bounds":                  {"grant", "issue", agent, "--principal", "user:" + user, "--expires", "48h"},
		"a missing bounds file":      {"grant", "issue", agent, "--principal", "user:" + user, "--expires", "48h", "--bounds-file", filepath.Join(dir, "nope")},
		"a revision of 0":            {"grant", "revise", "g1", "--bounds-file", bounds},
		"an unknown state":           {"grant", "list", "--state", "paused"},
		"an unknown scope":           {"guardrail", "create", "--scope", "galaxy:1", "--name", "x", "--bounds-file", bounds},
		"a bad fact":                 {"fact-provider", "register", "--name", "crm", "--sa", user, "--fact", "crm.vip:boolean"},
		"an unknown fact type":       {"fact-provider", "register", "--name", "crm", "--sa", user, "--fact", "crm.vip:text:crm.customer:5m"},
		"an unknown package state":   {"package", "transition", "pc.mock-payments", "1.0.0", "--to", "gone"},
		"no policy file":             {"policy", "create"},
	} {
		if code, _, errs := run(t, env, args...); code != 1 || errs == "" {
			t.Errorf("%s: %d %q, want a refusal", name, code, errs)
		}
	}
	if code, _, errs := run(t, env, "grant", "revise", "g1", "--revision", "2", "--bounds-file", bounds, "--expires", "2027-01-01T00:00:00Z"); code != 0 ||
		r.revise.GetRevision() != 2 || r.revise.GetExpireTime().AsTime().Year() != 2027 {
		t.Fatalf("grant revise = %d %q, sent %v", code, errs, r.revise)
	}
	if code, _, _ := run(t, env, "grant", "list", "--agent", agent, "--state", "active"); code != 0 ||
		r.grants.GetAgentId() != agent || r.grants.GetState() != pantherclawv1.GrantState_GRANT_STATE_ACTIVE {
		t.Fatalf("grant list sent %v", r.grants)
	}

	if code, _, errs := run(t, env, "guardrail", "create", "--scope", "team:"+agent, "--name", "payments", "--bounds-file", bounds,
		"--max-root-lifetime", "72h", "--max-depth", "1"); code != 0 {
		t.Fatalf("guardrail create = %d %q", code, errs)
	}
	e := r.envelope
	if e.GetScope().GetKind() != pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_TEAM || e.GetScope().GetId() != agent ||
		e.GetSettings().GetMaxRootLifetime().AsDuration() != 72*time.Hour || e.GetSettings().GetMaxDepth() != 1 ||
		e.GetSettings().MaxChildren != nil || e.GetSettings().GetRepeatWindow() != nil {
		t.Fatalf("guardrail create sent %v", e)
	}
	if code, _, _ := run(t, env, "guardrail", "create", "--scope", "service_account:"+user, "--name", "ci", "--bounds-file", bounds); code != 0 ||
		r.envelope.GetScope().GetKind() != pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_PRINCIPAL ||
		r.envelope.GetScope().GetPrincipal().GetKind() != "service_account" {
		t.Fatalf("principal guardrail sent %v", r.envelope)
	}

	if code, _, errs := run(t, env, "fact-provider", "register", "--name", "billing", "--sa", user,
		"--fact", "payments.charge.refundable:boolean:payments.charge:5m"); code != 0 || len(r.provider.GetFacts()) != 1 ||
		r.provider.GetFacts()[0].GetType() != pantherclawv1.FactType_FACT_TYPE_BOOLEAN || r.provider.GetFacts()[0].GetMaxLag().AsDuration() != 5*time.Minute {
		t.Fatalf("fact-provider register = %d %q, sent %v", code, errs, r.provider)
	}
	value := writeTemp(t, dir, "value.json", "{\"bool\": true}\n")
	if code, _, errs := run(t, env, "fact", "put", "--name", "payments.charge.refundable", "--subject-type", "payments.charge",
		"--subject-id", "ch_1", "--value-file", value); code != 0 || string(r.facts.GetObservations()[0].GetValue()) != `{"bool": true}` ||
		time.Since(r.facts.GetObservations()[0].GetObserveTime().AsTime()) > time.Minute {
		t.Fatalf("fact put = %d %q, sent %v", code, errs, r.facts)
	}

	targets, pkg := writeTemp(t, dir, "targets.jws", "eyJ.payload.sig\n"), writeTemp(t, dir, "package.yaml", "format: 1\n")
	if code, _, errs := run(t, env, "package", "import", "--name", "pc.mock-payments", "--version", "1.0.0", "--targets-file", targets,
		"--file", pkg); code != 0 || r.imported.GetTargets() != "eyJ.payload.sig" || string(r.imported.GetPackage()) != "format: 1\n" {
		t.Fatalf("package import = %d %q, sent %v", code, errs, r.imported)
	}
	if code, _, _ := run(t, env, "package", "transition", "pc.mock-payments", "1.0.0", "--to", "active"); code != 0 ||
		r.moved.GetState() != pantherclawv1.PackageState_PACKAGE_STATE_ACTIVE || r.moved.GetVersion() != "1.0.0" {
		t.Fatalf("package transition sent %v", r.moved)
	}
	bundle := writeTemp(t, dir, "bundle.json", `{"id": "refunds", "rules": []}`)
	if code, out, _ := run(t, env, "policy", "create", "--file", bundle); code != 0 || string(r.policy.GetBundle()) != `{"id": "refunds", "rules": []}` ||
		!strings.Contains(out, "DRAFT") {
		t.Fatalf("policy create = %d %q, sent %v", code, out, r.policy)
	}
}
