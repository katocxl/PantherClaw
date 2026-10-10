// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// Holds and tasks (G0 M6 design decision 15, HR-185, PAP-1 §8).
//
// A held tools/call is remembered by its canonical action without the
// action id, which names the org, connection, run, instance, tool target
// and parameters. An identical call by the same run and instance on the
// same connection reuses the held action id, so an approval binds to it;
// any changed argument is a new action. A client that declares the tasks
// extension gets a task instead of a held tool error: polling it resubmits
// the same action with the poll's own credentials, so the Authority runs
// the whole pipeline again, and only the run, instance and connection that
// created it can see it.
//
// Both live only in this gateway's memory, for at most a hold's default
// deadline; a restart forgets them, and the agent's next identical call
// starts a new action.
const (
	// holdTTL is how long a hold or task is remembered: the default hold
	// deadline (G0 M5 part 2, decision 6).
	holdTTL = time.Hour
	// taskPollMs is the polling interval suggested to clients.
	taskPollMs = 5000
	// Memory bounds: entries (holds and tasks) per instance and in all,
	// and the bytes of the actions tasks keep. Beyond them a hold is not
	// remembered and a task is not created, which only costs the agent a
	// new action.
	maxPerInstance = 32
	maxEntries     = 2000
	maxTaskBytes   = 64 << 20
)

const (
	extTasks         = "io.modelcontextprotocol/tasks"
	metaCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// Task statuses (tasks extension).
const (
	statusWorking   = "working"
	statusCompleted = "completed"
	statusCancelled = "cancelled" //nolint:misspell // the tasks extension spells it so
)

// binding is who a hold or task belongs to (HR-185): the connection, the
// run and the instance, in this gateway's org.
type binding struct {
	conn, run, instance string
}

type key [sha256.Size]byte

type hold struct {
	binding binding
	action  string
	expires time.Time
}

// task is one MCP task: a held call the client polls.
type task struct {
	id               string
	binding          binding
	action           actionir.Parsed
	key              key
	created, updated time.Time
	expires          time.Time
	status           string
	result           *toolResult
	// busy: a poll is resubmitting the action; other polls only read.
	busy bool
}

type store struct {
	now   func() time.Time
	mu    sync.Mutex
	holds map[key]hold
	tasks map[string]*task
	bytes int
}

func newStore(now func() time.Time) *store {
	return &store{now: now, holds: map[key]hold{}, tasks: map[string]*task{}}
}

// actionKey identifies a call without its action id: two calls with equal
// keys are the same tool call by the same run and instance on the same
// connection.
func actionKey(a actionir.ActionIR) key {
	a.ActionID = ""
	b, _ := json.Marshal(a)
	v := jsontext.Value(b)
	_ = v.Canonicalize()
	return sha256.Sum256(v)
}

// purgeLocked drops what expired.
func (s *store) purgeLocked(now time.Time) {
	for k, h := range s.holds {
		if !now.Before(h.expires) {
			delete(s.holds, k)
		}
	}
	for id, t := range s.tasks {
		if !now.Before(t.expires) {
			s.dropLocked(id)
		}
	}
}

func (s *store) dropLocked(id string) {
	if t, ok := s.tasks[id]; ok {
		s.bytes -= len(t.action.Canonical)
		delete(s.tasks, id)
	}
}

// fullLocked reports whether another entry for the instance, keeping
// extra bytes, would pass the bounds.
func (s *store) fullLocked(instance string, extra int) bool {
	if len(s.holds)+len(s.tasks) >= maxEntries || s.bytes+extra > maxTaskBytes {
		return true
	}
	n := 0
	for _, h := range s.holds {
		if h.binding.instance == instance {
			n++
		}
	}
	for _, t := range s.tasks {
		if t.binding.instance == instance {
			n++
		}
	}
	return n >= maxPerInstance
}

// heldAction returns the action id of an open hold on the same call.
func (s *store) heldAction(k key) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[k]
	if !ok || !s.now().Before(h.expires) {
		return "", false
	}
	return h.action, true
}

// settle records what an answer means for the call's hold. A hold is
// remembered (within the bounds). An answer without a transaction decided
// nothing (the gateway refused before asking, or the Authority could not
// be asked), so an open hold stays. Anything else ends it.
func (s *store) settle(k key, b binding, action string, res dispatch.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case res.Class == dispatch.Held:
		now := s.now()
		s.purgeLocked(now)
		if _, ok := s.holds[k]; ok || !s.fullLocked(b.instance, 0) {
			s.holds[k] = hold{binding: b, action: action, expires: now.Add(holdTTL)}
		}
	case res.TransactionID != "":
		delete(s.holds, k)
	}
}

// newTask returns a task for a held call: the open one for the same call,
// or a new one. It returns nil when the bounds are reached (the client then
// gets the held tool error) or no random id could be made.
func (s *store) newTask(b binding, a actionir.Parsed, k key) *task {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.purgeLocked(now)
	for _, t := range s.tasks {
		if t.key == k && t.binding == b && t.status == statusWorking && t.action.Action.ActionID == a.Action.ActionID {
			cp := *t
			return &cp
		}
	}
	if s.fullLocked(b.instance, len(a.Canonical)) {
		return nil
	}
	t := &task{
		id: base64.RawURLEncoding.EncodeToString(raw[:]), binding: b, action: a, key: k,
		created: now, updated: now, expires: now.Add(holdTTL), status: statusWorking,
	}
	s.tasks[t.id] = t
	s.bytes += len(a.Canonical)
	cp := *t
	return &cp
}

// lookup returns a task of this binding; any other binding, or an expired
// task, is not found (HR-185). resubmit claims a working task for this
// poll, which then resubmits it and must call finish or release.
func (s *store) lookup(id string, b binding, resubmit bool) (snapshot task, claimed, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok || t.binding != b || !s.now().Before(t.expires) {
		return task{}, false, false
	}
	if resubmit && t.status == statusWorking && !t.busy {
		t.busy, claimed = true, true
	}
	return *t, claimed, true
}

// finish records a resubmission's answer: still held, or completed with
// the tool result (a tool error included). A task canceled meanwhile is
// answered from the poll's copy.
func (s *store) finish(snap task, res dispatch.Result, result toolResult) task {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[snap.id]
	if !ok {
		t = &snap
		t.status = statusCancelled
	}
	t.busy, t.updated = false, s.now()
	if res.Class != dispatch.Held {
		t.status, t.result = statusCompleted, &result
	}
	return *t
}

// release ends a claim that produced no answer.
func (s *store) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[id]; ok {
		t.busy = false
	}
}

// cancel forgets a task of this binding and the hold of its call, so the
// next identical call is a new action; it reports whether there was one.
func (s *store) cancel(id string, b binding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok || t.binding != b {
		return false
	}
	delete(s.holds, t.key)
	s.dropLocked(id)
	return true
}

// supportsTasks reports whether a request's client capabilities declare
// the tasks extension; only then may a task be returned.
func supportsTasks(meta map[string]jsontext.Value) bool {
	var caps struct {
		Extensions map[string]jsontext.Value `json:"extensions"`
	}
	if v, ok := meta[metaCapabilities]; !ok || json.Unmarshal(v, &caps) != nil {
		return false
	}
	_, ok := caps.Extensions[extTasks]
	return ok
}

// taskResult is a task as clients see it: a CreateTaskResult (resultType
// "task") or a GetTaskResult (resultType "complete", with the tool's
// result once completed).
type taskResult struct {
	ResultType     string         `json:"resultType"`
	TaskID         string         `json:"taskId"`
	Status         string         `json:"status"`
	StatusMessage  string         `json:"statusMessage,omitzero"`
	CreatedAt      string         `json:"createdAt"`
	LastUpdatedAt  string         `json:"lastUpdatedAt"`
	TTLMs          int64          `json:"ttlMs"`
	PollIntervalMs int            `json:"pollIntervalMs,omitzero"`
	Result         *toolResult    `json:"result,omitzero"`
	Meta           map[string]any `json:"_meta,omitzero"`
}

// view is the task as clients see it; txn is the held transaction, when
// this answer has one.
func (t task) view(resultType, txn string) taskResult {
	out := taskResult{
		ResultType: resultType, TaskID: t.id, Status: t.status, CreatedAt: t.created.UTC().Format(time.RFC3339Nano),
		LastUpdatedAt: t.updated.UTC().Format(time.RFC3339Nano), TTLMs: holdTTL.Milliseconds(), Result: t.result,
	}
	if t.status == statusWorking {
		out.PollIntervalMs = taskPollMs
		out.StatusMessage = "Held for approval or step-up. Keep polling: PantherClaw decides again on each poll and runs the call once it is allowed."
		if txn != "" {
			out.Meta = map[string]any{metaHold: map[string]any{"transaction_id": txn, "retry_after_s": taskPollMs / 1000}}
		}
	}
	return out
}
