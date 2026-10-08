// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
	"time"
)

// refundPackage is a valid two-operation package used across the tests.
func refundPackage() *Package {
	reviewed := Assurance{Basis: BasisDocumented, ReviewedBy: []string{"Joshua Kato"}, ValidUntil: "2027-10-08"}
	return &Package{
		Format: Format, Name: "pc.mock-payments", Version: "1.0.0", Publisher: "pantherclaw",
		Summary: "Simulated payments API (SIMULATED)",
		Definitions: []Definition{{
			Operation: "payments.refund.create", Summary: "Refund part or all of a charge", Access: AccessWrite,
			Target: TargetSpec{Type: "payments.charge", IDPattern: `^ch_[A-Za-z0-9]{1,64}$`, Account: PresenceNone},
			Params: map[string]ParamSpec{
				"amount": {Type: TypeMoney, Material: true, Required: true, Currencies: []string{"USD", "EUR"}, Max: "100000"},
				"reason": {Type: TypeEnum, Material: true, Required: true, Values: []string{"duplicate", "fraudulent"}},
				"note":   {Type: TypeText, MaxLength: 500},
			},
			Effects:       []Effect{{Kind: "funds.transfer", Description: "Returns funds to the customer"}},
			Reversibility: Irreversible,
			Constraints:   []ConstraintSpec{{Kind: ConstraintAmountMax, Param: "amount"}},
			Prerequisites: []Prerequisite{{Fact: "payments.charge.refundable", MaxAgeSeconds: 300}},
			Retry:         RetrySpec{OnUnknown: OnUnknownReconcile, TargetIdempotency: true},
			Verifier:      &VerifierSpec{Operation: "payments.refund.get", Establishes: "refund.exists", WithinSeconds: 600},
			Approval: &ApprovalTemplate{
				Title: "Refund {params.amount} on charge {target.id}", Fields: []string{"params.amount", "params.reason", "target.id"},
			},
			Dedupe:    []string{"target.id", "params.amount"},
			Assurance: reviewed,
			Mappings: []Mapping{
				{Channel: ChannelMCP, Tool: "refund_charge", Route: "payments-refund", Extract: Extract{
					TargetID: "input.charge",
					Params:   map[string]string{"amount": "money(input.amount, input.currency)", "reason": "input.reason"},
				}},
				{Channel: ChannelHTTP, Method: "POST", Path: "/v1/charges/{charge}/refunds", Route: "payments-refund", Extract: Extract{
					TargetID: "path.charge",
					Params:   map[string]string{"amount": "money(input.amount, input.currency)", "reason": "input.reason"},
				}},
			},
		}, {
			Operation: "payments.refund.get", Summary: "Read a refund", Access: AccessRead,
			Target:        TargetSpec{Type: "payments.refund", IDPattern: `^re_[A-Za-z0-9]{1,64}$`, Account: PresenceNone},
			Effects:       []Effect{{Kind: "none", Description: "Reads only"}},
			Reversibility: Reversible, Retry: RetrySpec{Safe: true, OnUnknown: OnUnknownFail}, Assurance: reviewed,
			Mappings: []Mapping{{Channel: ChannelMCP, Tool: "get_refund", Route: "payments-refund-get", Extract: Extract{TargetID: "input.refund"}}},
		}},
	}
}

func TestReferencePackageIsValid(t *testing.T) {
	if err := refundPackage().Validate(); err != nil {
		t.Fatal(err)
	}
}

func create(p *Package) *Definition { return &p.Definitions[0] }

// mutations each break exactly one rule of a valid package.
var mutations = map[string]func(p *Package){
	"format":                 func(p *Package) { p.Format = 2 },
	"package name":           func(p *Package) { p.Name = "Mock Payments" },
	"version":                func(p *Package) { p.Version = "1.0" },
	"no definitions":         func(p *Package) { p.Definitions = nil },
	"duplicate operation":    func(p *Package) { p.Definitions[1].Operation = "payments.refund.create" },
	"operation":              func(p *Package) { create(p).Operation = "Refund" },
	"access":                 func(p *Package) { create(p).Access = "admin" },
	"reversibility":          func(p *Package) { create(p).Reversibility = "maybe" },
	"no effects":             func(p *Package) { create(p).Effects = nil },
	"effect kind":            func(p *Package) { create(p).Effects[0].Kind = "Funds Transfer" },
	"target type":            func(p *Package) { create(p).Target.Type = "" },
	"unanchored id pattern":  func(p *Package) { create(p).Target.IDPattern = `ch_[A-Za-z0-9]+` },
	"bad id pattern":         func(p *Package) { create(p).Target.IDPattern = `^ch_(?P<x$` },
	"account presence":       func(p *Package) { create(p).Target.Account = "sometimes" },
	"account pattern unused": func(p *Package) { create(p).Target.AccountPattern = `^acct_[a-z]+$` },
	"param name":             func(p *Package) { create(p).Params["Amount"] = ParamSpec{Type: TypeBoolean} },
	"param type":             func(p *Package) { create(p).Params["flag"] = ParamSpec{Type: "float"} },
	"enum without values":    func(p *Package) { create(p).Params["kind"] = ParamSpec{Type: TypeEnum} },
	"values on identifier":   func(p *Package) { create(p).Params["id"] = ParamSpec{Type: TypeIdentifier, Values: []string{"a"}} },
	"list without max_items": func(p *Package) { create(p).Params["ids"] = ParamSpec{Type: TypeIdentifierList} },
	"bounds on enum": func(p *Package) {
		create(p).Params["kind"] = ParamSpec{Type: TypeEnum, Values: []string{"a"}, Max: "1"}
	},
	"non-canonical bound":    func(p *Package) { create(p).Params["rows"] = ParamSpec{Type: TypeInteger, Unit: "rows", Max: "1.5"} },
	"constraint kind":        func(p *Package) { create(p).Constraints[0].Kind = "magic" },
	"constraint param type":  func(p *Package) { create(p).Constraints[0].Param = "reason" },
	"constraint no param":    func(p *Package) { create(p).Constraints[0] = ConstraintSpec{Kind: ConstraintAmountMax} },
	"prerequisite age":       func(p *Package) { create(p).Prerequisites[0].MaxAgeSeconds = 0 },
	"retry on_unknown":       func(p *Package) { create(p).Retry.OnUnknown = "ignore" },
	"irreversible retry":     func(p *Package) { create(p).Retry.Safe = true },
	"irreversible fail":      func(p *Package) { create(p).Retry.OnUnknown = OnUnknownFail },
	"verifier missing":       func(p *Package) { create(p).Verifier.Operation = "payments.refund.list" },
	"verifier is a write":    func(p *Package) { create(p).Verifier.Operation = "payments.refund.create" },
	"verifier window":        func(p *Package) { create(p).Verifier.WithinSeconds = 0 },
	"write without approval": func(p *Package) { create(p).Approval = nil },
	"approval no fields":     func(p *Package) { create(p).Approval.Fields = nil },
	"approval unknown field": func(p *Package) { create(p).Approval.Fields = []string{"params.missing"} },
	"approval account":       func(p *Package) { create(p).Approval.Fields = []string{"target.account"} },
	"assurance basis":        func(p *Package) { create(p).Assurance.Basis = "vibes" },
	"assurance reviewers":    func(p *Package) { create(p).Assurance.ReviewedBy = nil },
	"assurance date":         func(p *Package) { create(p).Assurance.ValidUntil = "next year" },
	"no mappings":            func(p *Package) { create(p).Mappings = nil },
	"channel":                func(p *Package) { create(p).Mappings[0].Channel = "sdk" },
	"mcp with method":        func(p *Package) { create(p).Mappings[0].Method = "POST" },
	"mcp tool name":          func(p *Package) { create(p).Mappings[0].Tool = "refund charge" },
	"http method":            func(p *Package) { create(p).Mappings[1].Method = "TRACE" },
	"http traversal":         func(p *Package) { create(p).Mappings[1].Path = "/v1/../admin" },
	"http encoded slash":     func(p *Package) { create(p).Mappings[1].Path = "/v1/a%2fb" },
	"http query in path":     func(p *Package) { create(p).Mappings[1].Path = "/v1/refunds?x=1" },
	"http repeated variable": func(p *Package) { create(p).Mappings[1].Path = "/v1/{charge}/{charge}" },
	"route":                  func(p *Package) { create(p).Mappings[0].Route = "Payments Refund" },
	"no target expression":   func(p *Package) { create(p).Mappings[0].Extract.TargetID = "" },
	"account expression":     func(p *Package) { create(p).Mappings[0].Extract.TargetAccount = "input.acct" },
	"undeclared param":       func(p *Package) { create(p).Mappings[0].Extract.Params["currency"] = "input.currency" },
	"missing required param": func(p *Package) { delete(create(p).Mappings[0].Extract.Params, "reason") },
	"empty param expression": func(p *Package) { create(p).Mappings[0].Extract.Params["reason"] = "" },
	"huge expression":        func(p *Package) { create(p).Mappings[0].Extract.TargetID = string(make([]byte, 5000)) },
	"destination kind": func(p *Package) {
		create(p).Mappings[0].Extract.Destinations = []DestinationExpr{{Kind: "public", ID: "x"}}
	},
	"duplicate tool": func(p *Package) { p.Definitions[1].Mappings[0].Tool = "refund_charge" },
	"same route renamed variable": func(p *Package) {
		m := create(p).Mappings[1]
		m.Path = "/v1/charges/{id}/refunds"
		p.Definitions[1].Mappings = append(p.Definitions[1].Mappings, m)
	},
}

func TestPackageValidationRejectsEachMutation(t *testing.T) {
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := refundPackage()
			mutate(p)
			if err := p.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestHR007_IrreversibleDefinitionRequiresDedupeKey(t *testing.T) {
	for name, key := range map[string][]string{
		"none":          nil,
		"operation":     {"operation"},
		"text param":    {"params.note"},
		"unknown param": {"params.missing"},
		"no account":    {"target.account"},
		"repeated":      {"target.id", "target.id"},
	} {
		p := refundPackage()
		create(p).Dedupe = key
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("dedupe_key %v: %v, want ErrInvalid", name, err)
		}
	}
	p := refundPackage()
	create(p).Reversibility = Compensatable
	create(p).Dedupe = nil
	if err := p.Validate(); err != nil {
		t.Fatalf("a compensatable operation may omit the dedupe key: %v", err)
	}
}

func TestHR023_TextIsNeverMaterialOrShownForApproval(t *testing.T) {
	p := refundPackage()
	note := create(p).Params["note"]
	note.Material = true
	create(p).Params["note"] = note
	if err := p.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("material text: %v, want ErrInvalid", err)
	}
	p = refundPackage()
	create(p).Approval.Title = "Refund because {params.note}"
	if err := p.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("text in the approval title: %v, want ErrInvalid", err)
	}
}

func TestHR102_PackageTextRejectsBidiAndControls(t *testing.T) {
	for _, s := range []string{"Refund \u202eetad", "Refund\x00", "zero\u200bwidth", "bad \xff"} {
		p := refundPackage()
		create(p).Summary = s
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("summary %q: %v, want ErrInvalid", s, err)
		}
	}
}

func TestHR103_UnsupportedUnitsAndCurrenciesAreInvalid(t *testing.T) {
	for name, spec := range map[string]ParamSpec{
		"unit":            {Type: TypeDecimal, Unit: "furlongs"},
		"missing unit":    {Type: TypeInteger},
		"unit on money":   {Type: TypeMoney, Currencies: []string{"USD"}, Unit: "count"},
		"currency":        {Type: TypeMoney, Currencies: []string{"XYZ"}},
		"lower currency":  {Type: TypeMoney, Currencies: []string{"usd"}},
		"no currencies":   {Type: TypeMoney},
		"pattern on text": {Type: TypeText, Pattern: "^a$"},
	} {
		p := refundPackage()
		create(p).Params["x"] = spec
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestOnlyCountMaxMayClamp(t *testing.T) {
	p := refundPackage()
	create(p).Constraints[0].Clamp = true
	if err := p.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("clamping a refund amount (F105): %v, want ErrInvalid", err)
	}
	p = refundPackage()
	create(p).Params["limit"] = ParamSpec{Type: TypeInteger, Unit: "rows", Min: "1", Max: "1000"}
	create(p).Constraints = append(create(p).Constraints, ConstraintSpec{Kind: ConstraintCountMax, Param: "limit", Clamp: true})
	if err := p.Validate(); err != nil {
		t.Fatalf("clamping a row limit: %v", err)
	}
	if c, ok := create(p).Supports(ConstraintCountMax, "limit"); !ok || !c.Clamp {
		t.Fatal("Supports(count_max, limit) should report the clamp")
	}
	if _, ok := create(p).Supports(ConstraintTargetSet, ""); ok {
		t.Fatal("an undeclared constraint must be unsupported (F100)")
	}
}

func TestTargetMatching(t *testing.T) {
	spec := TargetSpec{Type: "a.b", IDPattern: `^ch_[a-z]+$`, Account: PresenceOptional, AccountPattern: `^acct_[a-z]+$`}
	for _, c := range []struct {
		id, account string
		want        bool
	}{
		{"ch_x", "", true},
		{"ch_x", "acct_y", true},
		{"xch_x", "", false},
		{"ch_x\n", "", false},
		{"ch_x", "acct_Y", false},
	} {
		if got := spec.MatchID(c.id) && spec.MatchAccount(c.account); got != c.want {
			t.Errorf("match(%q, %q) = %v, want %v", c.id, c.account, got, c.want)
		}
	}
	spec.Account = PresenceRequired
	if spec.MatchAccount("") {
		t.Error("a required account must be present")
	}
	spec.Account = PresenceNone
	if spec.MatchAccount("acct_y") {
		t.Error("an account must be absent when the target has none")
	}
}

func TestVersionsAndAssurance(t *testing.T) {
	a, _ := ParseVersion("1.10.0")
	b, _ := ParseVersion("1.9.12")
	if a2, _ := ParseVersion("1.10.0"); a.Compare(b) <= 0 || b.Compare(a) >= 0 || a.Compare(a2) != 0 || a.String() != "1.10.0" {
		t.Fatal("versions must compare numerically")
	}
	if _, err := ParseVersion("01.0.0"); !errors.Is(err, ErrInvalid) {
		t.Fatal("leading zeros must be rejected")
	}
	as := Assurance{ValidUntil: "2027-10-08"}
	if as.Stale(time.Date(2027, 10, 8, 23, 59, 0, 0, time.UTC)) || !as.Stale(time.Date(2027, 10, 9, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("assurance is valid through the end of valid_until (UTC)")
	}
	if !(Assurance{ValidUntil: "soon"}).Stale(time.Time{}) {
		t.Fatal("an unparsable date counts as stale")
	}
}
