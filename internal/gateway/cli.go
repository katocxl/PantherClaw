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
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// bearer adds the dev gateway token to control-plane requests. The token is
// never logged.
type bearer struct {
	token pclog.Secret[[]byte]
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b.token.Reveal()))
	return b.base.RoundTrip(r)
}

// New builds a Gateway from a validated configuration.
func New(cfg *Config, log *slog.Logger) (*Gateway, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	token, err := config.ReadSecretFile(cfg.Authority.TokenFile)
	if err != nil {
		return nil, err
	}
	authURL, _ := baseURL(cfg.Authority.URL)
	target, _ := baseURL(cfg.Target.URL)
	prefixes, _ := cfg.allowedPrefixes()
	// Control-plane clients are separate from the egress client (HR-074).
	control := httpx.NewControlClient(httpx.ControlConfig{Timeout: cfg.Authority.Timeout.D()})
	authed := httpx.NewControlClient(httpx.ControlConfig{
		Timeout: cfg.Authority.Timeout.D(),
		Wrap:    func(rt http.RoundTripper) http.RoundTripper { return bearer{token: token, base: rt} },
	})
	return &Gateway{
		org:       cfg.Org,
		authority: pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(authed, authURL.String()))),
		permits:   newPermitVerifier(authURL.JoinPath(".well-known", "pantherclaw", "jwks.json").String(), control, cfg.GatewayID, cfg.Org),
		egress:    httpx.NewEgressClient(httpx.EgressConfig{Timeout: cfg.Target.Timeout.D(), AllowedPrefixes: prefixes}),
		target:    target,
		publicURL: strings.TrimSuffix(cfg.PublicURL, "/"),
		log:       log,
	}, nil
}

const usage = `pantherclaw-gateway — PantherClaw gateway (M1.5 walking skeleton, development only)

Usage:
  pantherclaw-gateway serve [--config FILE]
  pantherclaw-gateway version

Configuration: JSON file plus PC_GW_* environment variables; secrets only as file paths.
`

// Run executes pantherclaw-gateway.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env config.LookupEnv) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-gateway"))
		return 0
	case "serve":
		err := serve(ctx, args[1:], stderr, env, nil)
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "pantherclaw-gateway: %v\n", err)
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
}

func serve(ctx context.Context, args []string, stderr io.Writer, env config.LookupEnv, onStart func(addr string)) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "JSON configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := DefaultConfig()
	if err := config.Load(&cfg, *path, env); err != nil {
		return err
	}
	level, _ := pclog.ParseLevel(cfg.Log.Level)
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-gateway", Version: version.Get().Version, Level: level})
	g, err := New(&cfg, log)
	if err != nil {
		return err
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: cfg.Listen, Handler: g.Handler(), Logger: log})
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.WarnContext(ctx, "gateway.listening", slog.String("addr", ln.Addr().String()),
		slog.String("note", "development only: dev workload headers and dev gateway token"))
	if onStart != nil {
		onStart(ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
