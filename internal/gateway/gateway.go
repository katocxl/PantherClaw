// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Deps are what the gateway takes from the control plane. New builds them
// over mutual TLS from the gateway's identity; tests build them directly.
type Deps struct {
	// Org and GatewayID come from the gateway's certificate (HR-181).
	Org       string
	GatewayID string
	Authority pantherclawv1connect.AuthorityServiceClient
	// JWKSURL and JWKSClient fetch the permit keys (from the gateway
	// listener, over mTLS).
	JWKSURL    string
	JWKSClient *http.Client
	// Run is background work (certificate renewal); nil for none.
	Run func(ctx context.Context) error
}

// New builds a Gateway for an enrolled identity.
func New(cfg *Config, id *control.Identity, log *slog.Logger) (*Gateway, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ctl := control.NewClient(id, cfg.Control.IdentityDir, cfg.Control.GatewayURL, cfg.Control.Timeout.D(), log)
	return newGateway(cfg, Deps{
		Org: id.Org.String(), GatewayID: id.Gateway.String(), Authority: ctl.Authority,
		JWKSURL: ctl.BaseURL() + "/.well-known/pantherclaw/jwks.json", JWKSClient: ctl.HTTPClient(), Run: ctl.Run,
	}, log)
}

func newGateway(cfg *Config, d Deps, log *slog.Logger) (*Gateway, error) {
	if d.Org == "" || d.GatewayID == "" || d.Authority == nil || d.JWKSClient == nil {
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
		org: d.Org, authority: d.Authority, run: d.Run,
		permits:   newPermitVerifier(d.JWKSURL, d.JWKSClient, d.GatewayID, d.Org),
		egress:    httpx.NewEgressClient(httpx.EgressConfig{Timeout: cfg.Target.Timeout.D(), AllowedPrefixes: prefixes}),
		target:    target,
		publicURL: strings.TrimSuffix(cfg.PublicURL, "/"),
		log:       log,
	}, nil
}

// Run does the gateway's background work until ctx ends.
func (g *Gateway) Run(ctx context.Context) error {
	if g.run == nil {
		<-ctx.Done()
		return nil
	}
	return g.run(ctx)
}

// WaitReady returns when the gateway may serve. (The containment snapshot
// arrives in a later slice; until then the gateway is ready at once.)
func (g *Gateway) WaitReady(ctx context.Context, _ time.Duration) error { return ctx.Err() }
