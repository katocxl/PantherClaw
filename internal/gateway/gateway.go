// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Containment is the gateway's view of its org's containment (HR-010):
// control.Containment, fed by the WatchContainment stream.
type Containment interface {
	// Check reports whether dispatch is allowed now, with the current epoch.
	Check() (int64, error)
	// Ready closes when the first snapshot arrived.
	Ready() <-chan struct{}
}

// Deps are what the gateway takes from the control plane. New builds them
// over mutual TLS from the gateway's identity; tests build them directly.
type Deps struct {
	// Org and GatewayID come from the gateway's certificate (HR-181).
	Org       string
	GatewayID string
	Authority pantherclawv1connect.AuthorityServiceClient
	// JWKSURL and JWKSClient fetch the permit keys (from the gateway
	// listener, over mTLS).
	JWKSURL     string
	JWKSClient  *http.Client
	Containment Containment
	// Run is background work (certificate renewal, the containment stream);
	// nil for none.
	Run []func(ctx context.Context) error
}

// New builds a Gateway for an enrolled identity.
func New(cfg *Config, id *control.Identity, log *slog.Logger) (*Gateway, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ctl := control.NewClient(id, cfg.Control.IdentityDir, cfg.Control.GatewayURL, cfg.Control.Timeout.D(), log)
	k := control.NewContainment(ctl, log)
	return newGateway(cfg, Deps{
		Org: id.Org.String(), GatewayID: id.Gateway.String(), Authority: ctl.Authority,
		JWKSURL: ctl.BaseURL() + "/.well-known/pantherclaw/jwks.json", JWKSClient: ctl.HTTPClient(),
		Containment: k, Run: []func(context.Context) error{ctl.Run, k.Run},
	}, log)
}

func newGateway(cfg *Config, d Deps, log *slog.Logger) (*Gateway, error) {
	if d.Org == "" || d.GatewayID == "" || d.Authority == nil || d.JWKSClient == nil || d.Containment == nil {
		return nil, errors.New("gateway: incomplete control-plane dependencies")
	}
	target, err := baseURL(cfg.Target.URL)
	if err != nil {
		return nil, err
	}
	prefixes, err := cfg.allowedPrefixes()
	if err != nil {
		return nil, err
	}
	return &Gateway{
		org: d.Org, authority: d.Authority, run: d.Run, containment: d.Containment,
		permits:   newPermitVerifier(d.JWKSURL, d.JWKSClient, d.GatewayID, d.Org),
		egress:    httpx.NewEgressClient(httpx.EgressConfig{Timeout: cfg.Target.Timeout.D(), AllowedPrefixes: prefixes}),
		target:    target,
		publicURL: strings.TrimSuffix(cfg.PublicURL, "/"),
		log:       log,
	}, nil
}

// Run does the gateway's background work until ctx ends.
func (g *Gateway) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, f := range g.run {
		eg.Go(func() error { return f(ctx) })
	}
	eg.Go(func() error { <-ctx.Done(); return nil })
	return eg.Wait()
}

// WaitReady returns once the first containment snapshot arrived: the
// gateway serves nothing before (HR-010).
func (g *Gateway) WaitReady(ctx context.Context, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-g.containment.Ready():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("gateway: no containment snapshot from the server within %s", timeout)
	}
}
