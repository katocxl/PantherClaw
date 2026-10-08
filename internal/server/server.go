// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package server wires pantherclaw-server: the control plane (API role),
// background workers (worker role), migrations and database bootstrap.
// cmd/pantherclaw-server only calls Run.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	"github.com/katocxl/pantherclaw/internal/evidence/chainer"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/tenancy/adapters/tenancyrpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

const usage = `pantherclaw-server — PantherClaw control plane

Usage:
  pantherclaw-server serve [--config FILE]            run the API and/or workers (role from config)
  pantherclaw-server migrate up|status [--config FILE] apply or show schema migrations (as pc_migrator)
  pantherclaw-server db bootstrap --admin-url-file F --app-password-file F --migrator-password-file F --audit-password-file F
                                                     create roles and schema once, as the database owner
  pantherclaw-server keys gen-kek --out FILE          write a new key-encryption key (0600)
  pantherclaw-server dev seed [--config FILE] [--org-name N] [--budget-limit X] [--max-count N] [--token-out FILE]
                                                     DEVELOPMENT ONLY: demo org, budget and gateway token
  pantherclaw-server version

Configuration: JSON file plus PC_* environment variables; secrets only as file paths.
`

// Env reads environment variables (os.LookupEnv in production).
type Env = config.LookupEnv

// Run executes pantherclaw-server; ctx is canceled on SIGINT/SIGTERM.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-server"))
		return 0
	case "serve":
		err = cmdServe(ctx, args[1:], stderr, env, nil)
	case "migrate":
		err = cmdMigrate(ctx, args[1:], stdout, stderr, env)
	case "db":
		err = cmdDB(ctx, args[1:], stdout, stderr)
	case "keys":
		err = cmdKeys(args[1:], stdout, stderr)
	case "dev":
		err = cmdDev(ctx, args[1:], stdout, stderr, env)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp), errors.Is(err, errUsage):
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "pantherclaw-server: %v\n", err)
		return 1
	}
}

var errUsage = errors.New("usage")

func loadConfig(args []string, stderr io.Writer, env Env, name string) (*Config, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "JSON configuration file")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	cfg := DefaultConfig()
	if err := config.Load(&cfg, *path, env); err != nil {
		return nil, nil, err
	}
	return &cfg, fs.Args(), nil
}

func newLogger(cfg *Config, w io.Writer) *slog.Logger {
	level, _ := pclog.ParseLevel(cfg.Log.Level)
	return pclog.New(w, pclog.Options{Service: "pantherclaw-server", Version: version.Get().Version, Level: level})
}

// started reports the bound API address to tests (nil in production).
type started func(apiAddr string)

func cmdServe(ctx context.Context, args []string, stderr io.Writer, env Env, onStart started) error {
	cfg, rest, err := loadConfig(args, stderr, env, "serve")
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errUsage
	}
	log := newLogger(cfg, stderr)
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, cfg.DB.MaxConns)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		return err
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, pool, kp, reg); err != nil {
		return err
	}
	bill, err := applyLicence(ctx, cfg, pool, log)
	if err != nil {
		return err
	}

	svc, err := newAuthority(cfg, pool, reg, log)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	if cfg.Role == RoleAPI || cfg.Role == RoleAll {
		gw, err := devGatewayAuth(cfg)
		if err != nil {
			return err
		}
		if gw != nil {
			log.WarnContext(ctx, "server.dev_gateway_enabled", slog.String("gateway_id", cfg.DevGateway.ID),
				slog.String("org", cfg.DevGateway.Org), slog.String("note", "development only; not for production"))
		}
		tokens, err := token.New(reg, cfg.Auth.PublicURL, token.Audience)
		if err != nil {
			return err
		}
		authn, err := authnapp.NewAuthenticator(pool, tokens, credential.Env(cfg.Auth.APIKeyEnv), clock.System{}, log)
		if err != nil {
			return err
		}
		handler, err := apiHandler(apiDeps{
			pool: pool, reg: reg, log: log, authority: svc, billing: bill,
			auth:      rpcauth.New(authn, procedurePermissions, gw),
			apiKeyEnv: credential.Env(cfg.Auth.APIKeyEnv),
			oauth: oauthhttp.New(authnapp.NewOAuth(pool, tokens, cfg.Auth.PublicURL, clock.System{}, log),
				cfg.Auth.PublicURL, httpx.NewLimiter(oauthRateLimit, time.Minute, nil)),
		})
		if err != nil {
			return err
		}
		srv, ln, err := listen(ctx, cfg, handler, log)
		if err != nil {
			return err
		}
		if onStart != nil {
			onStart(ln.Addr().String())
		}
		log.InfoContext(ctx, "server.listening", slog.String("addr", ln.Addr().String()), slog.String("role", cfg.Role))
		g.Go(func() error {
			var err error
			if srv.TLSConfig != nil {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
		g.Go(func() error {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
			defer cancel()
			return srv.Shutdown(sctx)
		})
	}
	if cfg.Role == RoleWorker || cfg.Role == RoleAll {
		jreg := jobs.NewRegistry()
		if err := chainer.Register(jreg, pool); err != nil {
			return err
		}
		if err := authority.RegisterSweeper(jreg, pool, svc, cfg.Authority.StaleDispatch.D()); err != nil {
			return err
		}
		client, err := jobs.NewClient(pool, jreg, jobs.Config{
			Queues:       map[string]int{river.QueueDefault: cfg.WorkerConcurrency},
			PeriodicJobs: slices.Concat(chainer.PeriodicJobs(), authority.SweeperPeriodicJobs()),
			Logger:       log,
		})
		if err != nil {
			return err
		}
		if err := client.Start(ctx); err != nil {
			return fmt.Errorf("server: start workers: %w", err)
		}
		log.InfoContext(ctx, "server.workers_started", slog.Int("concurrency", cfg.WorkerConcurrency))
		g.Go(func() error {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
			defer cancel()
			return client.Stop(sctx)
		})
	}
	err = g.Wait()
	log.InfoContext(context.WithoutCancel(ctx), "server.stopped")
	return err
}

func listen(ctx context.Context, cfg *Config, handler http.Handler, log *slog.Logger) (*http.Server, net.Listener, error) {
	var tlsConf *tls.Config
	if cfg.HTTP.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("server: TLS key pair: %w", err)
		}
		tlsConf = httpx.ServerTLSConfig(cert)
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{
		Addr: cfg.HTTP.Addr, Handler: handler, TLS: tlsConf,
		PlaintextBehindProxy: cfg.HTTP.PlaintextBehindProxy, Logger: log,
	})
	if err != nil {
		return nil, nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.HTTP.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("server: listen: %w", err)
	}
	return srv, ln, nil
}

// publicProcedures run without authentication; each is declared
// "permission: public" in its proto (tested).
func publicProcedures() []string {
	return []string{pantherclawv1connect.SystemServiceGetBuildInfoProcedure}
}

// apiDeps are the API role's dependencies. auth authenticates users,
// service accounts and API keys, and delegates AuthorityService to the
// development gateway (refused when it is off).
type apiDeps struct {
	pool      *db.Pool
	reg       *keys.Registry
	log       *slog.Logger
	authority *authority.Service
	billing   *billing.Service
	auth      rpc.Authenticator
	apiKeyEnv credential.Env
	oauth     *oauthhttp.Handler
}

// apiHandler mounts the RPC services, health endpoints and the JWKS.
func apiHandler(d apiDeps) (http.Handler, error) {
	pool, reg, log := d.pool, d.reg, d.log
	rs, err := rpc.NewServer(rpc.Options{
		Logger:       log,
		Public:       publicProcedures(),
		Authenticate: d.auth,
	})
	if err != nil {
		return nil, err
	}
	pantherclawv1connect.RegisterSystemServiceHandler(rs, systemService{})
	pantherclawv1connect.RegisterAuthorityServiceHandler(rs, authority.NewHandler(d.authority))
	pantherclawv1connect.RegisterTenancyServiceHandler(rs, tenancyrpc.NewTenancy(tapp.NewHierarchy(pool, d.billing)))
	pantherclawv1connect.RegisterAccessServiceHandler(rs, tenancyrpc.NewAccess(tapp.NewAccess(pool, log)))
	pantherclawv1connect.RegisterServiceAccountServiceHandler(rs, tenancyrpc.NewServiceAccounts(tapp.NewServiceAccounts(pool, d.apiKeyEnv)))
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
	d.oauth.Mount(mux)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		err := pool.InGlobalTx(ctx, db.GlobalHealth, func(ctx context.Context, tx db.GlobalTx) error {
			var one int
			return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
		}, db.ReadOnly())
		if err != nil {
			log.WarnContext(ctx, "server.not_ready", pclog.Err(err))
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("GET /.well-known/pantherclaw/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		b, err := reg.JWKS()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(b)
	})
	return mux, nil
}

// startupActor records start-up actions in the audit log.
var startupActor = evdomain.Actor{Type: "system", ID: "server-startup"}

func applyLicence(ctx context.Context, cfg *Config, pool *db.Pool, log *slog.Logger) (*billing.Service, error) {
	roots, err := licence.EmbeddedRoots()
	if err != nil {
		return nil, err
	}
	svc := billing.New(pool, roots, clock.System{}, log)
	if cfg.LicenceFile != "" {
		doc, err := os.ReadFile(cfg.LicenceFile)
		if err != nil {
			return nil, fmt.Errorf("server: licence file: %w", err)
		}
		// An invalid licence is recorded and audited, and the server keeps
		// running with Community limits (founder decision 2026-10-08).
		if _, err := svc.Install(ctx, doc, startupActor); err != nil && !errors.Is(err, licence.ErrInvalid) {
			return nil, err
		}
	}
	e, err := svc.Current(ctx)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "licence.status", slog.String("edition", string(e.Edition)), slog.String("status", string(e.Status)),
		slog.Int("max_agents", e.Limits.MaxAgents), slog.Int("max_orgs", e.Limits.MaxOrgs))
	return svc, nil
}

func cmdMigrate(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	sub := args[0]
	cfg, rest, err := loadConfig(args[1:], stderr, env, "migrate "+sub)
	if err != nil {
		return err
	}
	if len(rest) != 0 || cfg.DB.MigratorPasswordFile == "" {
		_, _ = fmt.Fprintln(stderr, "migrate needs database.migrator_password_file")
		return errUsage
	}
	mc, err := cfg.dbConfig(cfg.DB.MigratorUser, cfg.DB.MigratorPasswordFile, 2)
	if err != nil {
		return err
	}
	switch sub {
	case "up":
		res, err := db.Migrate(ctx, mc)
		if err != nil {
			return err
		}
		for _, r := range res {
			_, _ = fmt.Fprintf(stdout, "applied %d %s\n", r.Version, r.Source)
		}
		v, err := db.MigrationVersion(ctx, mc)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "schema version %d\n", v)
		return nil
	case "status":
		v, err := db.MigrationVersion(ctx, mc)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "schema version %d\n", v)
		return nil
	default:
		return errUsage
	}
}

func cmdDB(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "bootstrap" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("db bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	adminURL := fs.String("admin-url-file", "", "file holding the owner/superuser connection URL for the target database")
	appPW := fs.String("app-password-file", "", "password file for pc_app")
	migPW := fs.String("migrator-password-file", "", "password file for pc_migrator")
	auditPW := fs.String("audit-password-file", "", "password file for pc_audit_ro")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *adminURL == "" || *appPW == "" || *migPW == "" || *auditPW == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	url, err := config.ReadSecretFile(*adminURL)
	if err != nil {
		return err
	}
	var pw db.RolePasswords
	for dst, path := range map[*pclog.Secret[[]byte]]string{&pw.App: *appPW, &pw.Migrator: *migPW, &pw.AuditRO: *auditPW} {
		s, err := config.ReadSecretFile(path)
		if err != nil {
			return err
		}
		*dst = s
	}
	cc, err := pgx.ParseConfig(string(url.Reveal()))
	if err != nil {
		return errors.New("db bootstrap: admin URL does not parse")
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return fmt.Errorf("db bootstrap: connect: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if err := db.BootstrapRoles(ctx, conn, pw); err != nil {
		return err
	}
	if err := db.BootstrapDatabase(ctx, conn); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "bootstrapped roles %s, %s, %s, %s and schema %s in database %s\n",
		db.RoleMigrator, db.RoleApp, db.RoleAuditRO, db.RoleLister, db.Schema, cc.Database)
	return nil
}

func cmdKeys(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "gen-kek" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("keys gen-kek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file (created with mode 0600, never overwritten)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	if err := keys.GenerateKEKFile(*out); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote key-encryption key to %s; keep it outside the repository and back it up securely\n", *out)
	return nil
}
