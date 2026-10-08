// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package payments is a simulated payments API for tests and demos
// (pantherclaw-sim payments). It refunds charges, requires an idempotency
// key, detects replays, and can inject latency, declines and hangs so that
// ALLOW, FAILED and UNKNOWN paths can be exercised. Every response is marked
// SIMULATED; nothing here moves real money.
package payments

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Faults configures fault injection. Rates are probabilities in [0, 1].
type Faults struct {
	Latency     time.Duration
	DeclineRate float64 // respond 402 card_declined (no effect)
	HangRate    float64 // never answer within the client's timeout (unknown outcome)
	HangFor     time.Duration
}

// Refund is one recorded refund.
type Refund struct {
	ID       string
	Charge   string
	Amount   money.Money
	Reason   string
	BodyHash [32]byte
}

// Server is the simulated payments API.
type Server struct {
	faults Faults
	log    *slog.Logger

	mu      sync.Mutex
	byKey   map[string]Refund
	total   money.Decimal
	count   int
	replays int
}

// New returns a simulator.
func New(f Faults, log *slog.Logger) *Server {
	if f.HangFor == 0 {
		f.HangFor = 30 * time.Second
	}
	return &Server{faults: f, log: log, byKey: map[string]Refund{}}
}

type refundRequest struct {
	Charge   string `json:"charge"`
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	Reason   string `json:"reason"`
}

var (
	chargePattern = regexp.MustCompile(`^ch_[A-Za-z0-9]{1,64}$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
)

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/refunds", s.refund)
	mux.HandleFunc("GET /v1/stats", s.stats)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

func (s *Server) refund(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	if !keyPattern.MatchString(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "idempotency_key_required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unreadable_body"})
		return
	}
	var req refundRequest
	if err := json.Unmarshal(body, &req, json.RejectUnknownMembers(true)); err != nil || !chargePattern.MatchString(req.Charge) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	amount, err := money.ParseMoney(req.Amount, req.Currency)
	if err != nil || amount.Amount.Sign() <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_amount"})
		return
	}
	hash := sha256.Sum256(body)

	if s.faults.Latency > 0 {
		select {
		case <-time.After(s.faults.Latency):
		case <-r.Context().Done():
			return
		}
	}
	if chance(s.faults.HangRate) {
		select {
		case <-time.After(s.faults.HangFor):
		case <-r.Context().Done():
		}
		// Drop the connection without a response: an empty 200 would look
		// like success to the caller.
		panic(http.ErrAbortHandler)
	}

	status, resp, replayed := s.apply(key, req, amount, hash)
	if replayed {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	writeJSON(w, status, resp)
}

// apply records the refund under the lock and returns the response to
// write; the network write happens outside the lock.
func (s *Server) apply(key string, req refundRequest, amount money.Money, hash [32]byte) (status int, resp any, replayed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byKey[key]; ok {
		if prev.BodyHash != hash {
			return http.StatusConflict, map[string]string{"error": "idempotency_key_reused_with_different_request"}, false
		}
		s.replays++
		return http.StatusOK, refundResponse{ID: prev.ID, Status: "succeeded", Simulated: true}, true
	}
	if chance(s.faults.DeclineRate) {
		return http.StatusPaymentRequired, map[string]string{"error": "card_declined"}, false
	}
	ref := Refund{ID: "re_" + ids.NewV7().String(), Charge: req.Charge, Amount: amount, Reason: req.Reason, BodyHash: hash}
	s.byKey[key] = ref
	s.count++
	if t, err := s.total.Add(amount.Amount); err == nil {
		s.total = t
	}
	return http.StatusOK, refundResponse{ID: ref.ID, Status: "succeeded", Simulated: true}, false
}

// Stats summarizes what the simulator has done.
type Stats struct {
	Refunds int    `json:"refunds"`
	Total   string `json:"total"`
	Replays int    `json:"replays"`
}

// Stats returns the current counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Refunds: s.count, Total: s.total.String(), Replays: s.replays}
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Stats())
}

// chance returns true with probability p, using crypto/rand (math/rand is
// banned in this repository).
func chance(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11)/float64(1<<53) < p
}

// refundResponse has a fixed field order so replays are byte-identical.
type refundResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Simulated bool   `json:"simulated"`
}
