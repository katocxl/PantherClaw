// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

// tokenRefresh is how often a load run renews its workload token, well
// inside the token's 10-minute lifetime (PAP-1 §3.4).
const tokenRefresh = 4 * time.Minute

// tokens holds the workload token the load signs its requests with.
type tokens struct {
	mu  sync.Mutex
	cur string
}

func (t *tokens) get() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur
}

func (t *tokens) set(v string) {
	t.mu.Lock()
	t.cur = v
	t.mu.Unlock()
}

// workloadTokens returns the token source for a load run: the token in
// tokenFile, or tokens issued by the key file's server and renewed until ctx
// ends.
func workloadTokens(ctx context.Context, kf workloadclient.KeyFile, tokenFile string) (func() string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile) //nolint:gosec // G304: operator-chosen path
		if err != nil {
			return nil, err
		}
		tok := strings.TrimSpace(string(b))
		return func() string { return tok }, nil
	}
	if kf.Server == "" || kf.Identifier == "" {
		return nil, errors.New("the workload key file names no server or identifier (seed it with `pantherclaw-server dev seed --workload-out`)")
	}
	key, err := kf.Key()
	if err != nil {
		return nil, err
	}
	client := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: key}}, kf.Server)))
	var t tokens
	issue := func() error {
		res, err := client.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier})
		if err != nil {
			return fmt.Errorf("workload token: %w", err)
		}
		t.set(res.GetWorkloadToken())
		return nil
	}
	if err := issue(); err != nil {
		return nil, err
	}
	go func() {
		tick := time.NewTicker(tokenRefresh)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = issue() // a failed renewal keeps the current token until it expires
			}
		}
	}()
	return t.get, nil
}
