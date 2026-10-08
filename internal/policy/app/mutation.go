// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
)

// flips maps each comparison to the mutation that most often survives weak
// tests: the boundary shift (< ↔ <=, > ↔ >=) and equality negation.
var flips = map[string]string{
	operators.Less: operators.LessEquals, operators.LessEquals: operators.Less,
	operators.Greater: operators.GreaterEquals, operators.GreaterEquals: operators.Greater,
	operators.Equals: operators.NotEquals, operators.NotEquals: operators.Equals,
}

// Mutants returns one mutant per comparison in a condition, each with that
// single comparison flipped (HR-044). A rule's scenario tests must fail on
// every mutant; a surviving mutant means a threshold or equality is not
// pinned by any test.
func Mutants(src string) ([]string, error) {
	env, err := cel.NewEnv()
	if err != nil {
		return nil, err
	}
	count := 0
	if _, err := mutate(env, src, -1, &count); err != nil {
		return nil, err
	}
	out := make([]string, 0, count)
	for i := range count {
		n := 0
		m, err := mutate(env, src, i, &n)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// mutate parses src and flips the target-th comparison (none when target is
// negative), counting comparisons in *n, and returns the unparsed result.
func mutate(env *cel.Env, src string, target int, n *int) (string, error) {
	a, iss := env.Parse(src)
	if iss.Err() != nil {
		return "", fmt.Errorf("mutants: %w", iss.Err())
	}
	fac := ast.NewExprFactory()
	ast.PreOrderVisit(a.NativeRep().Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() != ast.CallKind {
			return
		}
		call := e.AsCall()
		flip, ok := flips[call.FunctionName()]
		if !ok {
			return
		}
		if *n == target {
			e.SetKindCase(fac.NewCall(e.ID(), flip, call.Args()...))
		}
		*n++
	}))
	return cel.AstToString(a)
}
