// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"slices"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
)

// noUnsafeNumbers rejects what makes amount comparisons wrong (HR-041):
// ordering operators on strings, bytes, doubles or values whose type is not
// known at check time (dyn), and any double-typed expression at all.
// Lexical "100" < "85" and IEEE rounding have no place in a policy.
type noUnsafeNumbers struct{}

func (noUnsafeNumbers) Name() string { return "pc.no_unsafe_numbers" }

var orderingOps = []string{operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals}

func unsafeOrdered(t *types.Type) bool {
	if t == nil {
		return true
	}
	switch t.Kind() { //nolint:exhaustive // every other kind is ordered exactly or not at all
	case types.StringKind, types.BytesKind, types.DoubleKind, types.DynKind, types.AnyKind, types.TypeParamKind, types.ErrorKind:
		return true
	}
	return false
}

func (noUnsafeNumbers) Validate(_ *cel.Env, _ cel.ValidatorConfig, a *ast.AST, iss *cel.Issues) {
	for id, t := range a.TypeMap() {
		if t.Kind() == types.DoubleKind {
			iss.ReportErrorAtID(id, "floating-point values are not allowed; use decimal() or money() (HR-041)")
		}
	}
	calls := ast.MatchDescendants(ast.NavigateAST(a), func(e ast.NavigableExpr) bool {
		return e.Kind() == ast.CallKind && slices.Contains(orderingOps, e.AsCall().FunctionName())
	})
	for _, c := range calls {
		for _, arg := range c.AsCall().Args() {
			if t := a.GetType(arg.ID()); unsafeOrdered(t) {
				iss.ReportErrorAtID(c.ID(), "ordering is not allowed on %s values; compare decimal() or money() amounts (HR-041)", typeName(t))
				break
			}
		}
	}
}

func typeName(t *types.Type) string {
	if t == nil {
		return "untyped"
	}
	return t.String()
}

// hasGuards requires every optional struct field to be guarded by has() on
// the path that selects it (HR-042): `has(x.f) && x.f …`, `!has(x.f) || x.f …`
// or `has(x.f) ? x.f … : …`. An unguarded optional field would make the rule
// error whenever the field is absent; the error fails closed, but a linted
// rule says what it means.
type hasGuards struct{ schema Schema }

func (hasGuards) Name() string { return "pc.has_guards" }

func (v hasGuards) Validate(_ *cel.Env, _ cel.ValidatorConfig, a *ast.AST, iss *cel.Issues) {
	selects := ast.MatchDescendants(ast.NavigateAST(a), ast.KindMatcher(ast.SelectKind))
	for _, e := range selects {
		sel := e.AsSelect()
		if sel.IsTestOnly() {
			continue
		}
		t := a.GetType(sel.Operand().ID())
		if t == nil || t.Kind() != types.StructKind {
			continue
		}
		f, ok := v.schema[t.TypeName()].Fields[sel.FieldName()]
		if !ok || !f.Optional {
			continue
		}
		p := path(e)
		if p == "" || !guarded(e, p) {
			iss.ReportErrorAtID(e.ID(), "optional field %s must be guarded by has() (HR-042)", sel.FieldName())
		}
	}
}

// path renders a select chain such as action.params.limit, or "" when the
// operand is not a plain chain of identifiers and selections.
func path(e ast.Expr) string {
	switch e.Kind() { //nolint:exhaustive // only identifiers and selections form a path
	case ast.IdentKind:
		return e.AsIdent()
	case ast.SelectKind:
		if op := path(e.AsSelect().Operand()); op != "" {
			return op + "." + e.AsSelect().FieldName()
		}
	}
	return ""
}

// guarded reports whether an ancestor condition proves the field present.
func guarded(e ast.NavigableExpr, p string) bool {
	child := e
	for parent, ok := e.Parent(); ok; parent, ok = parent.Parent() {
		if parent.Kind() == ast.CallKind {
			call := parent.AsCall()
			args := call.Args()
			switch {
			case call.FunctionName() == operators.LogicalAnd && len(args) == 2 && args[1].ID() == child.ID():
				if tests(args[0], p, false) {
					return true
				}
			case call.FunctionName() == operators.LogicalOr && len(args) == 2 && args[1].ID() == child.ID():
				if tests(args[0], p, true) {
					return true
				}
			case call.FunctionName() == operators.Conditional && len(args) == 3:
				if (args[1].ID() == child.ID() && tests(args[0], p, false)) ||
					(args[2].ID() == child.ID() && tests(args[0], p, true)) {
					return true
				}
			}
		}
		child = parent
	}
	return false
}

// tests reports whether cond contains has(p) (or !has(p) when negated)
// as a conjunct of a top-level && chain.
func tests(cond ast.Expr, p string, negated bool) bool {
	if cond.Kind() != ast.CallKind {
		return !negated && cond.Kind() == ast.SelectKind && cond.AsSelect().IsTestOnly() && path(cond) == p
	}
	call := cond.AsCall()
	switch call.FunctionName() {
	case operators.LogicalAnd:
		if negated {
			return false
		}
		return slices.ContainsFunc(call.Args(), func(a ast.Expr) bool { return tests(a, p, false) })
	case operators.LogicalNot:
		return negated && len(call.Args()) == 1 && tests(call.Args()[0], p, false)
	}
	return false
}

// Fields returns the top-level fields of a map variable that the program
// reads, by plain selection (v.f), optional selection (v.?f), presence test
// (has(v.f)) or constant index (v["f"]). ok is false when the variable is
// used in any other way, for example passed whole to a function or
// iterated: then the set of fields read cannot be known.
func (p *Program) Fields(variable string) (fields []string, ok bool) {
	for _, e := range ast.MatchDescendants(ast.NavigateAST(p.ast), ast.KindMatcher(ast.IdentKind)) {
		if e.AsIdent() != variable {
			continue
		}
		parent, found := e.Parent()
		if !found {
			return nil, false
		}
		switch parent.Kind() { //nolint:exhaustive // any other use of the variable is opaque
		case ast.SelectKind:
			fields = append(fields, parent.AsSelect().FieldName())
			continue
		case ast.CallKind:
			call := parent.AsCall()
			args := call.Args()
			if (call.FunctionName() == operators.OptSelect || call.FunctionName() == operators.Index) &&
				len(args) == 2 && args[0].ID() == e.ID() && args[1].Kind() == ast.LiteralKind {
				if s, isStr := args[1].AsLiteral().Value().(string); isStr {
					fields = append(fields, s)
					continue
				}
			}
		}
		return nil, false
	}
	slices.Sort(fields)
	return slices.Compact(fields), true
}
