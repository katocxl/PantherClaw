// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jobs

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type goodArgs struct {
	Org     ids.OrgID     `json:"org"`
	Entries []ids.OrgID   `json:"entries"`
	Reason  string        `json:"reason"`
	Count   int           `json:"count"`
	Due     time.Time     `json:"due"`
	Wait    time.Duration `json:"wait"`
	Force   bool          `json:"force"`
}

func (goodArgs) Kind() string { return "test.good" }

type goodWorker struct{ river.WorkerDefaults[goodArgs] }

func (goodWorker) Work(context.Context, *river.Job[goodArgs]) error { return nil }

func TestHR056_ArgsCarryIdentifiersOnly(t *testing.T) {
	if err := CheckArgs(reflect.TypeFor[goodArgs]()); err != nil {
		t.Fatalf("good args rejected: %v", err)
	}
	bad := map[string]any{
		"secret wrapper": struct{ Org pclog.Secret[string] }{},
		"bytes":          struct{ Blob []byte }{},
		"map":            struct{ Attrs map[string]string }{},
		"interface":      struct{ Value any }{},
		"pointer":        struct{ Org *ids.OrgID }{},
		"nested struct":  struct{ Inner struct{ X int } }{},
		"token name":     struct{ AccessToken string }{},
		"payload name":   struct{ RequestBody string }{},
		"password name":  struct{ DBPassword string }{},
		"float":          struct{ Amount float64 }{},
	}
	for name, v := range bad {
		if err := CheckArgs(reflect.TypeOf(v)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckArgs(reflect.TypeFor[int]()); err == nil {
		t.Error("non-struct args accepted")
	}
}

type leakyArgs struct {
	Org   ids.OrgID `json:"org"`
	Token string    `json:"token"`
}

func (leakyArgs) Kind() string { return "test.leaky" }

type leakyWorker struct {
	river.WorkerDefaults[leakyArgs]
}

func (leakyWorker) Work(context.Context, *river.Job[leakyArgs]) error { return nil }

func TestRegisterRefusesLeakyArgs(t *testing.T) {
	r := NewRegistry()
	if err := Register[goodArgs](r, goodWorker{}); err != nil {
		t.Fatal(err)
	}
	if err := Register[leakyArgs](r, leakyWorker{}); err == nil {
		t.Fatal("worker with a token argument registered")
	}
	if err := Register[goodArgs](r, goodWorker{}); err == nil {
		t.Fatal("duplicate kind registered")
	}
	if k := r.Kinds(); len(k) != 1 || k[0] != "test.good" {
		t.Fatalf("kinds = %v", k)
	}
}
