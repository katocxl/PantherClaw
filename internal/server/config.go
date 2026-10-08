// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Roles a server process can run.
const (
	RoleAPI    = "api"
	RoleWorker = "worker"
	RoleAll    = "all"
)

// Config is the pantherclaw-server configuration (JSON file + PC_* env).
// Secrets are referenced by file path only (SB-7).
type Config struct {
	Role string     `json:"role" env:"PC_ROLE"`
	Log  LogConfig  `json:"log"`
	HTTP HTTPConfig `json:"http"`
	DB   DBConfig   `json:"database"`
	// KEKFiles are key-encryption-key files; the first wraps new keys.
	KEKFiles    []string `json:"kek_files" env:"PC_KEK_FILES"`
	LicenceFile string   `json:"licence_file" env:"PC_LICENCE_FILE"`
	// WorkerConcurrency is the number of concurrent jobs per worker process.
	WorkerConcurrency int `json:"worker_concurrency" env:"PC_WORKER_CONCURRENCY"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level string `json:"level" env:"PC_LOG_LEVEL"`
}

// HTTPConfig configures the API listener.
type HTTPConfig struct {
	Addr                 string `json:"addr" env:"PC_HTTP_ADDR"`
	TLSCertFile          string `json:"tls_cert_file" env:"PC_HTTP_TLS_CERT_FILE"`
	TLSKeyFile           string `json:"tls_key_file" env:"PC_HTTP_TLS_KEY_FILE"`
	PlaintextBehindProxy bool   `json:"plaintext_behind_proxy" env:"PC_HTTP_PLAINTEXT_BEHIND_PROXY"`
}

// DBConfig configures PostgreSQL access.
type DBConfig struct {
	Host                 string          `json:"host" env:"PC_DB_HOST"`
	Port                 int             `json:"port" env:"PC_DB_PORT"`
	Name                 string          `json:"name" env:"PC_DB_NAME"`
	SSLMode              string          `json:"sslmode" env:"PC_DB_SSLMODE"`
	SSLRootCert          string          `json:"sslrootcert" env:"PC_DB_SSLROOTCERT"`
	AppUser              string          `json:"app_user" env:"PC_DB_APP_USER"`
	AppPasswordFile      string          `json:"app_password_file" env:"PC_DB_APP_PASSWORD_FILE"`
	MigratorUser         string          `json:"migrator_user" env:"PC_DB_MIGRATOR_USER"`
	MigratorPasswordFile string          `json:"migrator_password_file" env:"PC_DB_MIGRATOR_PASSWORD_FILE"`
	MaxConns             int             `json:"max_conns" env:"PC_DB_MAX_CONNS"`
	StatementTimeout     config.Duration `json:"statement_timeout" env:"PC_DB_STATEMENT_TIMEOUT"`
	LockTimeout          config.Duration `json:"lock_timeout" env:"PC_DB_LOCK_TIMEOUT"`
	IdleInTxTimeout      config.Duration `json:"idle_in_transaction_timeout" env:"PC_DB_IDLE_IN_TX_TIMEOUT"`
}

// DefaultConfig returns safe defaults: loopback listener, TLS-verified DB.
func DefaultConfig() Config {
	d := db.Defaults()
	return Config{
		Role: RoleAll,
		Log:  LogConfig{Level: "info"},
		HTTP: HTTPConfig{Addr: "127.0.0.1:8080"},
		DB: DBConfig{
			Host: d.Host, Port: d.Port, Name: d.Database, SSLMode: d.SSLMode,
			AppUser: db.RoleApp, MigratorUser: db.RoleMigrator, MaxConns: int(d.MaxConns),
			StatementTimeout: config.Duration(d.StatementTimeout), LockTimeout: config.Duration(d.LockTimeout),
			IdleInTxTimeout: config.Duration(d.IdleInTxTimeout),
		},
		WorkerConcurrency: 10,
	}
}

// Validate implements config.Validator.
func (c *Config) Validate() error {
	var errs []error
	if !slices.Contains([]string{RoleAPI, RoleWorker, RoleAll}, c.Role) {
		errs = append(errs, fmt.Errorf("role must be %s, %s or %s", RoleAPI, RoleWorker, RoleAll))
	}
	if _, ok := pclog.ParseLevel(c.Log.Level); !ok {
		errs = append(errs, errors.New("log.level must be debug, info, warn or error"))
	}
	if (c.HTTP.TLSCertFile == "") != (c.HTTP.TLSKeyFile == "") {
		errs = append(errs, errors.New("http.tls_cert_file and http.tls_key_file must be set together"))
	}
	if c.DB.AppPasswordFile == "" {
		errs = append(errs, errors.New("database.app_password_file is required"))
	}
	if c.DB.AppUser == db.RoleMigrator || c.DB.AppUser == "postgres" {
		errs = append(errs, errors.New("database.app_user must be the unprivileged application role"))
	}
	if len(c.KEKFiles) == 0 {
		errs = append(errs, errors.New("kek_files is required (generate one with: pantherclaw-server keys gen-kek --out FILE)"))
	}
	if c.WorkerConcurrency < 1 || c.WorkerConcurrency > 1000 {
		errs = append(errs, errors.New("worker_concurrency must be 1..1000"))
	}
	return errors.Join(errs...)
}

// dbConfig builds a pool configuration for user with the password from file.
func (c *Config) dbConfig(user, passwordFile string, maxConns int) (db.Config, error) {
	pw, err := config.ReadSecretFile(passwordFile)
	if err != nil {
		return db.Config{}, err
	}
	return db.Config{
		Host: c.DB.Host, Port: c.DB.Port, Database: c.DB.Name, User: user, Password: pw,
		SSLMode: c.DB.SSLMode, SSLRootCert: c.DB.SSLRootCert,
		MaxConns:         int32(maxConns), //nolint:gosec // G115: validated by db.Config.Validate (≤ 1000)
		StatementTimeout: c.DB.StatementTimeout.D(), LockTimeout: c.DB.LockTimeout.D(),
		IdleInTxTimeout: c.DB.IdleInTxTimeout.D(), ApplicationName: "pantherclaw-server",
		RequireUnprivileged: user != c.DB.MigratorUser,
	}, nil
}

// shutdownGrace bounds graceful shutdown.
const shutdownGrace = 20 * time.Second
