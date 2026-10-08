// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"fmt"
	"maps"
	"reflect"
	"slices"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// Field is one field of a struct type.
type Field struct {
	Type *types.Type
	// Optional fields may be absent at runtime; expressions must guard them
	// with has() (HR-042).
	Optional bool
}

// Struct is a struct type that expressions can select fields from. Struct
// types let the checker type every field, so an amount is a pc.Money and
// ordering a string field is a type error rather than a lexical comparison.
type Struct struct {
	Name   string
	Fields map[string]Field
}

// Type returns the CEL type of the struct.
func (s Struct) Type() *types.Type { return types.NewObjectType(s.Name) }

// Schema is the set of struct types of an environment, by name.
type Schema map[string]Struct

// Record is a runtime value of a struct type. Fields holds the present
// fields only; selecting an absent field is an evaluation error.
type Record struct {
	TypeName string
	Fields   map[string]ref.Val
}

var _ ref.Val = (*Record)(nil)

// ConvertToNative implements ref.Val.
func (r *Record) ConvertToNative(t reflect.Type) (any, error) {
	if reflect.TypeOf(r) == t {
		return r, nil
	}
	return nil, fmt.Errorf("%s cannot convert to %v", r.TypeName, t)
}

// ConvertToType implements ref.Val.
func (r *Record) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return types.NewObjectType(r.TypeName)
	}
	if t.TypeName() == r.TypeName {
		return r
	}
	return types.NewErr("%s cannot convert to %s", r.TypeName, t.TypeName())
}

// Equal implements ref.Val: same type, same fields, equal values.
func (r *Record) Equal(o ref.Val) ref.Val {
	s, ok := o.(*Record)
	if !ok || s.TypeName != r.TypeName || len(s.Fields) != len(r.Fields) {
		return types.False
	}
	for k, v := range r.Fields {
		w, ok := s.Fields[k]
		if !ok || v.Equal(w) != types.True {
			return types.False
		}
	}
	return types.True
}

// Type implements ref.Val.
func (r *Record) Type() ref.Type { return types.NewObjectType(r.TypeName) }

// Value implements ref.Val. It returns the record itself, which is what the
// field getters below receive.
func (r *Record) Value() any { return r }

// provider resolves the schema's struct types and delegates everything else
// to the default registry. Struct values cannot be constructed in
// expressions: only the caller builds records.
type provider struct {
	*types.Registry
	schema Schema
}

func (p *provider) FindStructType(name string) (*types.Type, bool) {
	if s, ok := p.schema[name]; ok {
		return types.NewTypeTypeWithParam(s.Type()), true
	}
	return p.Registry.FindStructType(name)
}

func (p *provider) FindStructFieldNames(name string) ([]string, bool) {
	if s, ok := p.schema[name]; ok {
		return slices.Sorted(maps.Keys(s.Fields)), true
	}
	return p.Registry.FindStructFieldNames(name)
}

func (p *provider) FindStructFieldType(name, field string) (*types.FieldType, bool) {
	s, ok := p.schema[name]
	if !ok {
		return p.Registry.FindStructFieldType(name, field)
	}
	f, ok := s.Fields[field]
	if !ok {
		return nil, false
	}
	return &types.FieldType{
		Type: f.Type,
		IsSet: func(obj any) bool {
			r, ok := obj.(*Record)
			if !ok {
				return false
			}
			_, set := r.Fields[field]
			return set
		},
		GetFrom: func(obj any) (any, error) {
			r, ok := obj.(*Record)
			if !ok || r.TypeName != name {
				return nil, fmt.Errorf("%s.%s: not a %s value", name, field, name)
			}
			v, set := r.Fields[field]
			if !set {
				return nil, fmt.Errorf("%s.%s is not set; guard it with has()", name, field)
			}
			return v, nil
		},
	}, true
}

func (p *provider) NewValue(name string, _ map[string]ref.Val) ref.Val {
	if _, ok := p.schema[name]; ok {
		return types.NewErr("%s values cannot be constructed in expressions", name)
	}
	return types.NewErr("unknown type %s", name)
}
