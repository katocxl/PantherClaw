// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Window is one weekly time window in UTC: Day from From (inclusive) to To
// (exclusive), as HH:MM, with To up to 24:00. There are no time zones in M4,
// so daylight saving can never open a gap or an overlap.
type Window struct {
	Day  string `json:"day"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Weekly is a set of windows; an action is allowed when its time falls in
// any of them. Weekly is a lattice over minute-of-week intervals.
type Weekly []Window

var days = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

const minutesPerDay = 24 * 60

func clock(s string, allow24 bool) (int, bool) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || mm < 0 || mm > 59 || hh < 0 {
		return 0, false
	}
	v := hh*60 + mm
	if v > minutesPerDay || (v == minutesPerDay && !allow24) {
		return 0, false
	}
	return v, true
}

// span is a half-open minute-of-week interval.
type span struct{ lo, hi int }

func (w Window) span() (span, error) {
	d := slices.Index(days, w.Day)
	from, ok1 := clock(w.From, false)
	to, ok2 := clock(w.To, true)
	if d < 0 || !ok1 || !ok2 || from >= to {
		return span{}, fmt.Errorf("window %s %s-%s: need a day (mon..sun) and HH:MM from < to (to up to 24:00)", w.Day, w.From, w.To)
	}
	return span{d*minutesPerDay + from, d*minutesPerDay + to}, nil
}

// spans returns sorted, merged intervals. Windows never cross midnight, and
// merging stops at day boundaries so the result maps back to windows.
func (w Weekly) spans() []span {
	var s []span
	for _, win := range w {
		if sp, err := win.span(); err == nil {
			s = append(s, sp)
		}
	}
	slices.SortFunc(s, func(a, b span) int { return a.lo - b.lo })
	var out []span
	for _, sp := range s {
		if n := len(out); n > 0 && sp.lo <= out[n-1].hi && sp.lo/minutesPerDay == out[n-1].lo/minutesPerDay {
			out[n-1].hi = max(out[n-1].hi, sp.hi)
			continue
		}
		out = append(out, sp)
	}
	return out
}

func fromSpans(s []span) Weekly {
	out := Weekly{}
	for _, sp := range s {
		d := sp.lo / minutesPerDay
		out = append(out, Window{Day: days[d], From: hhmm(sp.lo - d*minutesPerDay), To: hhmm(sp.hi - d*minutesPerDay)})
	}
	return out
}

func hhmm(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

func (w Weekly) validate(name string) error {
	if len(w) > maxEntries {
		return invalid("%s: at most %d windows", name, maxEntries)
	}
	for _, win := range w {
		if _, err := win.span(); err != nil {
			return invalid("%s: %v", name, err)
		}
	}
	return nil
}

// MinuteOfWeek returns t's minute of the week in UTC, Monday 00:00 = 0.
func MinuteOfWeek(t time.Time) int {
	t = t.UTC()
	d := (int(t.Weekday()) + 6) % 7 // Monday first
	return d*minutesPerDay + t.Hour()*60 + t.Minute()
}

// Contains reports whether minute m of the week is inside a window.
func (w Weekly) Contains(m int) bool {
	return slices.ContainsFunc(w.spans(), func(s span) bool { return s.lo <= m && m < s.hi })
}

// Within reports whether every minute w allows is allowed by p, or returns a
// window of w that p does not cover.
func (w Weekly) Within(p Weekly) (string, bool) {
	ps := p.spans()
	for _, s := range w.spans() {
		// Merged spans of p never touch within a day, so one must hold s.
		if !slices.ContainsFunc(ps, func(q span) bool { return q.lo <= s.lo && s.hi <= q.hi }) {
			win := fromSpans([]span{s})[0]
			return win.Day + " " + win.From + "-" + win.To, false
		}
	}
	return "", true
}

// Intersect returns the minutes both allow.
func (w Weekly) Intersect(p Weekly) Weekly {
	var out []span
	for _, a := range w.spans() {
		for _, b := range p.spans() {
			if lo, hi := max(a.lo, b.lo), min(a.hi, b.hi); lo < hi {
				out = append(out, span{lo, hi})
			}
		}
	}
	slices.SortFunc(out, func(a, b span) int { return a.lo - b.lo })
	return fromSpans(out)
}

// String renders the windows for explanations.
func (w Weekly) String() string {
	var parts []string
	for _, win := range fromSpans(w.spans()) {
		parts = append(parts, win.Day+" "+win.From+"-"+win.To+" UTC")
	}
	if len(parts) == 0 {
		return "never"
	}
	return strings.Join(parts, ", ")
}
