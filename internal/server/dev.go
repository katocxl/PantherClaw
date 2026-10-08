// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// devSeedActor records `dev seed` in the audit log.
var devSeedActor = evdomain.Actor{Type: "operator", ID: "dev-seed"}

// newAuthority builds the Transaction Authority with the configured
// development grant (M1.5: one hard-coded grant, no policy engine yet).
func newAuthority(cfg *Config, pool *db.Pool, reg *keys.Registry, log *slog.Logger) (*authority.Service, error) {
	maxPer, err := money.ParseMoney(cfg.Authority.GrantMaxPerAction, cfg.Authority.GrantCurrency)
	if err != nil {
		return nil, fmt.Errorf("server: authority grant: %w", err)
	}
	return authority.New(pool, reg, authority.Config{
		Grant: domain.DevGrant{
			Name: "dev-" + cfg.Authority.BudgetName, Operation: actionir.OpRefundCreate,
			MaxPerAction: maxPer, BudgetName: cfg.Authority.BudgetName,
		},
		PermitTTL: cfg.Authority.PermitTTL.D(),
		Logger:    log,
	}), nil
}

// devGatewayAuth returns the development gateway authenticator, or nil when
// the dev gateway is disabled (every non-public procedure is then refused).
func devGatewayAuth(cfg *Config) (rpc.Authenticator, error) {
	if !cfg.DevGateway.Enabled {
		return nil, nil
	}
	token, err := config.ReadSecretFile(cfg.DevGateway.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("server: dev gateway token: %w", err)
	}
	if len(token.Reveal()) < 32 {
		return nil, errors.New("server: dev gateway token is too short (use `pantherclaw-server dev seed --token-out FILE`)")
	}
	org, err := ids.Parse[ids.Org](cfg.DevGateway.Org)
	if err != nil {
		return nil, err
	}
	return authority.DevGatewayAuthenticator(sha256.Sum256(token.Reveal()), authority.Gateway{ID: cfg.DevGateway.ID, Org: org}), nil
}

// cmdDev implements `dev seed`: a demo org with its containment row and
// budget, and optionally a new development gateway token. DEVELOPMENT ONLY.
func cmdDev(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 || args[0] != "seed" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("dev seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	name := fs.String("org-name", "dev-org", "name of the new org")
	limit := fs.String("budget-limit", "1000.00", "budget limit in the grant currency")
	maxCount := fs.Int("max-count", 0, "optional limit on the number of committed actions (0 = none)")
	tokenOut := fs.String("token-out", "", "write a new dev gateway token here (0600, never overwritten)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *maxCount < 0 {
		fs.Usage()
		return errUsage
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "dev seed")
	if err != nil {
		return err
	}
	lim, err := money.ParseMoney(*limit, cfg.Authority.GrantCurrency)
	if err != nil || lim.Amount.Sign() <= 0 {
		return fmt.Errorf("dev seed: --budget-limit must be a positive %s amount", cfg.Authority.GrantCurrency)
	}
	var count *int32
	if *maxCount > 0 {
		c := int32(min(*maxCount, 1<<30))
		count = &c
	}
	if *tokenOut != "" {
		if err := writeDevToken(*tokenOut); err != nil {
			return err
		}
	}
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, 2)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	org := ids.New[ids.Org]()
	budget := ids.NewV7()
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, *name); err != nil {
			return fmt.Errorf("dev seed: org: %w", err)
		}
		q := dbq.New(tx)
		if err := q.InsertContainment(ctx, org); err != nil {
			return fmt.Errorf("dev seed: containment: %w", err)
		}
		if err := q.InsertBudget(ctx, dbq.InsertBudgetParams{
			OrgID: org, ID: budget, Name: cfg.Authority.BudgetName, Currency: string(lim.Currency),
			LimitAmount: lim.Amount, MaxCount: count,
		}); err != nil {
			return fmt.Errorf("dev seed: budget: %w", err)
		}
		details := map[string]string{"budget": cfg.Authority.BudgetName, "limit": lim.Amount.String(), "currency": string(lim.Currency)}
		if count != nil {
			details["max_count"] = strconv.Itoa(int(*count))
		}
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "dev.org_seeded", Actor: devSeedActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()}, Details: details,
		})
		return err
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded org %s (%q) with budget %s = %s %s\n", org, *name, cfg.Authority.BudgetName, lim.Amount, lim.Currency)
	_, _ = fmt.Fprintf(stdout, "enable the development gateway in the server config:\n"+
		"  \"dev_gateway\": {\"enabled\": true, \"org\": %q, \"gateway_id\": %q, \"token_file\": %q}\n",
		org.String(), cfg.DevGateway.ID, *tokenOut)
	return nil
}

// writeDevToken writes 32 random bytes, base64url-encoded, to a new 0600 file.
func writeDevToken(path string) error {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return fmt.Errorf("dev seed: token file: %w", err)
	}
	if _, err := io.WriteString(f, base64.RawURLEncoding.EncodeToString(b[:])+"\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("dev seed: token file: %w", err)
	}
	return f.Close()
}
