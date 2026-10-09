// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// cmdBrokerKey runs `broker-key generate`: a new broker key, wrapped with a
// key-encryption key file (G0 M6 design decision 8). It prints the
// fingerprint, which whoever seals credentials compares (pclaw seal
// --fingerprint).
func cmdBrokerKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("usage: pantherclaw-gateway broker-key generate --out FILE --kek-file FILE")
	}
	fs := flag.NewFlagSet("broker-key generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "where to write the broker key (never overwritten)")
	kek := fs.String("kek-file", "", "key-encryption key file (pantherclaw-server keys gen-kek)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || *kek == "" || fs.NArg() != 0 {
		return errors.New("broker-key generate needs --out and --kek-file")
	}
	fp, err := broker.Generate(ctx, *out, []string{*kek})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "broker key %s written to %s; give this fingerprint to whoever seals credentials\n", fp, *out)
	return err
}

// Broker is the gateway's broker key once the server registered it (G0 M6
// design decision 8): the gateway registers its public key over mTLS at
// start, as a new version when it differs from the active one, and opens
// credentials only with the id the server gave it.
type Broker struct {
	key      *broker.Key
	register func(ctx context.Context, public []byte) (string, error)
	log      *slog.Logger

	mu    sync.RWMutex
	id    string
	ready chan struct{}
	once  sync.Once
}

// NewBroker returns a broker that registers key with register.
func NewBroker(key *broker.Key, register func(ctx context.Context, public []byte) (string, error), log *slog.Logger) *Broker {
	if log == nil {
		log = pclog.Discard()
	}
	return &Broker{key: key, register: register, log: log, ready: make(chan struct{})}
}

// Run registers the key, retrying with backoff until it succeeds or ctx
// ends.
func (b *Broker) Run(ctx context.Context) error {
	wait := time.Second
	for {
		id, err := b.register(ctx, b.key.PublicKey())
		if err == nil {
			b.mu.Lock()
			b.id = id
			b.mu.Unlock()
			b.once.Do(func() { close(b.ready) })
			b.log.InfoContext(ctx, "gateway.broker_key_registered", slog.String("fingerprint", b.key.Fingerprint()), slog.String("broker_key_id", id))
			return nil
		}
		b.log.WarnContext(ctx, "gateway.broker_key_registration_failed", pclog.Err(err))
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// Ready closes once the key is registered.
func (b *Broker) Ready() <-chan struct{} { return b.ready }

// Open opens a sealed credential for one dispatch (see broker.Key.Open).
func (b *Broker) Open(org, connection string, allowedHosts []string, s broker.Sealed) ([]byte, error) {
	if b == nil {
		return nil, broker.ErrNoBroker
	}
	b.mu.RLock()
	id := b.id
	b.mu.RUnlock()
	return b.key.Open(org, connection, allowedHosts, id, s)
}
