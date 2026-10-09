// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m6Templates are the kill-switch notification types (G0 M6, HR-113). Like
// every template they render only ids and fixed text (HR-158) and link to
// the authenticated emergency-stop page; nothing in a message can engage or
// restore.
var m6Templates = []Template{
	{
		Type: "security.kill_switch_engaged", Severity: Critical, Params: []string{"user"},
		Title: "The PantherClaw kill switch was engaged",
		Body: "The org kill switch was engaged by {user}. Every agent action is refused until two people restore it " +
			"on the emergency-stop page.",
		Link: "/containment",
	},
	{
		Type: "security.kill_switch_restore_proposed", Severity: Warning, Params: []string{"user"},
		Title: "Lifting the kill switch is waiting for a second person",
		Body: "{user} proposed to lift the org kill switch. A different person must confirm it on the emergency-stop " +
			"page within 30 minutes, or it expires.",
		Link: "/containment",
	},
	{
		Type: "security.kill_switch_restore_canceled", Severity: Info, Params: []string{"user"},
		Title: "A proposal to lift the kill switch was canceled",
		Body:  "{user} canceled the proposal to lift the org kill switch. The kill switch stays engaged.",
		Link:  "/containment",
	},
	{
		Type: "security.kill_switch_restored", Severity: Warning, Params: []string{"user"},
		Title: "The PantherClaw kill switch was lifted",
		Body:  "{user} confirmed lifting the org kill switch. Agent actions are decided again.",
		Link:  "/containment",
	},
}

func init() { templates = append(templates, m6Templates...) }
