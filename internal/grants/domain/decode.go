// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"regexp"
	"slices"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// Limits of a bounds document.
const (
	MaxBoundsBytes = 64 << 10
	maxBoundsDepth = 8
)

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}$`)

func validOperation(op string) bool { return actionir.ValidOperation(op) }

// DecodeBounds strictly decodes a bounds document (HR-100): duplicate keys,
// unknown fields, nulls, numbers, excessive depth or size are refused, and
// the result is validated. A null would otherwise read as "unrestricted".
func DecodeBounds(raw []byte) (Bounds, error) {
	if len(raw) == 0 || len(raw) > MaxBoundsBytes {
		return Bounds{}, invalid("bounds: size %d outside 1..%d bytes", len(raw), MaxBoundsBytes)
	}
	if err := scanBounds(raw); err != nil {
		return Bounds{}, err
	}
	var b Bounds
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return Bounds{}, invalid("bounds: %v", err)
	}
	if err := b.Validate(); err != nil {
		return Bounds{}, err
	}
	return b, nil
}

func scanBounds(raw []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return invalid("bounds: %v", err)
		}
		k := tok.Kind()
		if k == jsontext.KindNull {
			return invalid("bounds: null is not allowed; leave the field out to leave it open")
		}
		if k == jsontext.KindNumber {
			return invalid("bounds: numbers are written as decimal strings (HR-101)")
		}
		if (k == jsontext.KindBeginObject || k == jsontext.KindBeginArray) && dec.StackDepth() > maxBoundsDepth {
			return invalid("bounds: nested deeper than %d", maxBoundsDepth)
		}
	}
}

// EncodeBounds returns the canonical JSON of b (sorted keys), which is what
// grant and envelope revisions store and hash.
func EncodeBounds(b Bounds) ([]byte, error) {
	return json.Marshal(b, json.Deterministic(true))
}

// TypeCheck checks every parameter bound against the operation's active
// definition: the parameter must exist, be material and have a type the
// bound fits, with the same unit, accepted currencies and enum values.
// lookup returns nil when the org has no active definition for op.
func (b Bounds) TypeCheck(lookup func(op string) *defs.Definition) error {
	for _, op := range slices.Sorted(maps.Keys(b.Params)) {
		d := lookup(op)
		if d == nil {
			return invalid("params.%s: no active definition for this operation", op)
		}
		for _, name := range slices.Sorted(maps.Keys(b.Params[op])) {
			if err := b.Params[op][name].fits(d.Params[name], "params."+op+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (pb ParamBound) fits(spec defs.ParamSpec, dim string) error {
	if spec.Type == "" {
		return invalid("%s: the definition has no such parameter", dim)
	}
	if !spec.Material {
		return invalid("%s: only material parameters can be bounded", dim)
	}
	switch {
	case pb.Range != nil:
		if spec.Type != defs.TypeInteger && spec.Type != defs.TypeDecimal {
			return invalid("%s: a range fits integer and decimal parameters, not %s", dim, spec.Type)
		}
		if pb.Range.Unit != "" && pb.Range.Unit != string(spec.Unit) {
			return invalid("%s: unit %q, but the parameter is in %q", dim, pb.Range.Unit, spec.Unit)
		}
	case pb.Max != nil:
		if spec.Type != defs.TypeMoney {
			return invalid("%s: max fits money parameters, not %s", dim, spec.Type)
		}
		for _, c := range slices.Sorted(maps.Keys(pb.Max)) {
			if !slices.Contains(spec.Currencies, c) {
				return invalid("%s: the parameter does not accept %s", dim, c)
			}
		}
	case pb.Values != nil:
		switch spec.Type { //nolint:exhaustive // only identifier-like types fit an allowlist
		case defs.TypeEnum:
			if len(pb.Values.Prefixes) > 0 {
				return invalid("%s: enum values cannot be prefixes", dim)
			}
			for _, v := range pb.Values.IDs {
				if !slices.Contains(spec.Values, v) {
					return invalid("%s: %q is not a value of the parameter", dim, v)
				}
			}
		case defs.TypeIdentifier, defs.TypeIdentifierList:
		default:
			return invalid("%s: values fit enum and identifier parameters, not %s", dim, spec.Type)
		}
	}
	return nil
}
