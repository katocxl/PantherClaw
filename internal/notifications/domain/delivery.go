// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"time"
)

// retrySchedule follows the Standard Webhooks example (which recommends
// exponential backoff; its last gap is 14 h) after each failed attempt:
// at once, then 5 s, 5 min, 30 min, 2 h, 5 h, 10 h and 10 h (8 attempts,
// about 27 hours in all).
var retrySchedule = []time.Duration{
	5 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour, 10 * time.Hour,
}

// MaxAttempts is the number of attempts of one delivery (HR-159): the
// first and one per entry of the schedule.
const MaxAttempts = 8

// RetryDelay is the wait after failed attempt n (1-based); the last delay is
// repeated if n is past the schedule.
func RetryDelay(n int) time.Duration {
	switch {
	case n < 1:
		return retrySchedule[0]
	case n > len(retrySchedule):
		return retrySchedule[len(retrySchedule)-1]
	}
	return retrySchedule[n-1]
}

// MaxRetryAfter caps a destination's Retry-After request.
const MaxRetryAfter = time.Hour

// Health of a channel, from its consecutive failures.
type Health string

// Health states.
const (
	Healthy  Health = "HEALTHY"
	Degraded Health = "DEGRADED"
	Failing  Health = "FAILING"
)

// FailingAfter is the number of consecutive failures that makes a channel
// FAILING; AutoPauseAfter is how long it may fail before it is paused.
const (
	FailingAfter   = 10
	AutoPauseAfter = 72 * time.Hour
)

// HealthOf summarizes consecutive failures.
func HealthOf(consecutiveFailures int) Health {
	switch {
	case consecutiveFailures <= 0:
		return Healthy
	case consecutiveFailures < FailingAfter:
		return Degraded
	}
	return Failing
}

// slackEscaper escapes the three characters Slack's mrkdwn treats as
// control characters, so text can never form a link or a mention (HR-158).
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// SlackEscape escapes text for a Slack message.
func SlackEscape(s string) string { return slackEscaper.Replace(s) }

// SlackText is the whole Slack message: escaped title and body and one
// link to the authenticated PantherClaw page. There are no buttons or
// actions (HR-033, F164, F166).
func SlackText(title, body, link string) string {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(SlackEscape(title))
	b.WriteString("*\n")
	b.WriteString(SlackEscape(body))
	if link != "" {
		b.WriteString("\n<")
		b.WriteString(SlackEscape(link))
		b.WriteString("|Open in PantherClaw>")
	}
	return b.String()
}
