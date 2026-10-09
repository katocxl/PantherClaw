// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"
)

// Schema is the reviewed input schema of an MCP tool: what MCP clients
// receive in tools/list (HR-081). It is a small JSON Schema subset: objects
// with closed properties, strings with patterns or enums, integers,
// booleans and arrays. There is no $ref, no composition and no format;
// every other keyword is refused when the package is decoded.
type Schema struct {
	Type        string `json:"type"`
	Description string `json:"description,omitzero"`
	// Objects.
	Properties           map[string]*Schema `json:"properties,omitzero"`
	Required             []string           `json:"required,omitzero"`
	AdditionalProperties *bool              `json:"additionalProperties,omitzero"`
	// Strings.
	Enum      []string `json:"enum,omitzero"`
	Pattern   string   `json:"pattern,omitzero"`
	MinLength int      `json:"minLength,omitzero"`
	MaxLength int      `json:"maxLength,omitzero"`
	// Integers.
	Minimum *int64 `json:"minimum,omitzero"`
	Maximum *int64 `json:"maximum,omitzero"`
	// Arrays.
	Items    *Schema `json:"items,omitzero"`
	MaxItems int     `json:"maxItems,omitzero"`
}

const (
	maxSchemaDepth = 4
	maxSchemaNodes = 256
	maxEnum        = 64
)

// validateSchema checks an input schema: the root is an object.
func validateSchema(at string, s *Schema) error {
	if s == nil || s.Type != "object" {
		return invalid("%s: the root of an input schema is an object", at)
	}
	nodes := 0
	return s.validate(at, 0, &nodes)
}

func (s *Schema) validate(at string, depth int, nodes *int) error {
	*nodes++
	switch {
	case *nodes > maxSchemaNodes:
		return invalid("%s: more than %d schema nodes", at, maxSchemaNodes)
	case depth > maxSchemaDepth:
		return invalid("%s: deeper than %d levels", at, maxSchemaDepth)
	}
	if s.Description != "" {
		if err := text(at+".description", s.Description); err != nil {
			return err
		}
	}
	object := len(s.Properties) > 0 || len(s.Required) > 0 || s.AdditionalProperties != nil
	str := len(s.Enum) > 0 || s.Pattern != "" || s.MinLength != 0 || s.MaxLength != 0
	integer := s.Minimum != nil || s.Maximum != nil
	array := s.Items != nil || s.MaxItems != 0
	switch s.Type {
	case "object":
		if str || integer || array {
			return invalid("%s: an object takes properties, required and additionalProperties only", at)
		}
		return s.validateObject(at, depth, nodes)
	case "string":
		if object || integer || array {
			return invalid("%s: a string takes enum, pattern, minLength and maxLength only", at)
		}
		return s.validateString(at)
	case "integer":
		if object || str || array {
			return invalid("%s: an integer takes minimum and maximum only", at)
		}
		if s.Minimum != nil && s.Maximum != nil && *s.Minimum > *s.Maximum {
			return invalid("%s: minimum above maximum", at)
		}
		return nil
	case "boolean":
		if object || str || integer || array {
			return invalid("%s: a boolean takes no keywords", at)
		}
		return nil
	case "array":
		if object || str || integer || s.Items == nil || s.MaxItems < 1 || s.MaxItems > maxListItems {
			return invalid("%s: an array takes items and maxItems 1..%d", at, maxListItems)
		}
		return s.Items.validate(at+".items", depth+1, nodes)
	default:
		return invalid("%s: type must be object, string, integer, boolean or array", at)
	}
}

func (s *Schema) validateObject(at string, depth int, nodes *int) error {
	if s.AdditionalProperties == nil || *s.AdditionalProperties {
		return invalid("%s: an object must set additionalProperties: false", at)
	}
	if len(s.Properties) > maxItems {
		return invalid("%s: at most %d properties", at, maxItems)
	}
	for _, name := range slices.Sorted(maps.Keys(s.Properties)) {
		if !fieldRe.MatchString(name) || s.Properties[name] == nil {
			return invalid("%s: property %q", at, name)
		}
		if err := s.Properties[name].validate(at+".properties."+name, depth+1, nodes); err != nil {
			return err
		}
	}
	for i, r := range s.Required {
		if s.Properties[r] == nil || slices.Contains(s.Required[:i], r) {
			return invalid("%s: required %q is not a property or appears twice", at, r)
		}
	}
	return nil
}

func (s *Schema) validateString(at string) error {
	switch {
	case s.MinLength < 0 || s.MaxLength < 0 || s.MaxLength > maxParamText || (s.MaxLength > 0 && s.MinLength > s.MaxLength):
		return invalid("%s: minLength and maxLength within 0..%d, minLength not above maxLength", at, maxParamText)
	case len(s.Enum) > maxEnum:
		return invalid("%s: at most %d enum values", at, maxEnum)
	}
	for i, v := range s.Enum {
		if v == "" || len(v) > 256 || slices.Contains(s.Enum[:i], v) {
			return invalid("%s: enum value %q is empty, too long or repeated", at, v)
		}
		if err := checkText(at+".enum", v); err != nil {
			return err
		}
	}
	if s.Pattern != "" {
		return anchored(at+".pattern", s.Pattern)
	}
	return nil
}
