// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"strings"
)

// PointerValue reads the scalar at a package's JSON pointer (ValidPointer)
// in a JSON document, as the text a target reports: a string without its
// quotes, a number or a boolean as written. It returns false for anything
// else: no such member or index, an object, an array, null, duplicate
// member names or invalid JSON. It reads what a verifier declares and
// nothing more (HR-190).
func PointerValue(doc []byte, ptr string) (string, bool) {
	if !ValidPointer(ptr) {
		return "", false
	}
	v := jsontext.Value(doc)
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch v.Kind() {
		case '{':
			var m map[string]jsontext.Value
			if json.Unmarshal(v, &m) != nil {
				return "", false
			}
			next, ok := m[tok]
			if !ok {
				return "", false
			}
			v = next
		case '[':
			var a []jsontext.Value
			i, err := strconv.Atoi(tok)
			if err != nil || json.Unmarshal(v, &a) != nil || i < 0 || i >= len(a) || (len(tok) > 1 && tok[0] == '0') {
				return "", false
			}
			v = a[i]
		default:
			return "", false
		}
	}
	switch v.Kind() {
	case '"':
		var s string
		if json.Unmarshal(v, &s) != nil {
			return "", false
		}
		return s, true
	case '0', 't', 'f':
		if !v.IsValid() {
			return "", false
		}
		return string(v), true
	}
	return "", false
}
