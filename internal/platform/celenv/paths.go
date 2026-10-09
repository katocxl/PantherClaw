// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// pathLibrary adds normpath(string) string: the one spelling of an
// absolute path (actionir.NormalizePath, HR-187). A path it refuses is an
// evaluation error, which a mapping reports as ambiguous.
func pathLibrary() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("normpath", cel.Overload("normpath_string", []*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				s, ok := v.(types.String)
				if !ok {
					return types.MaybeNoSuchOverloadErr(v)
				}
				p, err := actionir.NormalizePath(string(s))
				if err != nil {
					return errVal(err)
				}
				return types.String(p)
			}))),
	}
}
