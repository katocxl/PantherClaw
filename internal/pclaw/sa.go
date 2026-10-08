// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// keyFile is what `pclaw sa key-generate` writes: the account's client id
// and its private key (JWK). It never leaves this machine.
type keyFile struct {
	ClientID string         `json:"client_id"`
	Key      jsontext.Value `json:"private_jwk"`
}

var keyAlgs = map[string]pantherclawv1.KeyAlgorithm{
	"EdDSA": pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_EDDSA, "ES256": pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_ES256,
}

func serviceAccountCommands() map[string]command {
	setState := func(state pantherclawv1.AccountState) func(*flag.FlagSet) call {
		return func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.sa.SetServiceAccountState(ctx, &pantherclawv1.SetServiceAccountStateRequest{Id: a[0], State: state})
			}
		}
	}
	return map[string]command{
		"sa create": rpc("sa create --name NAME [--description D]", 0, func(fs *flag.FlagSet) call {
			name, desc := fs.String("name", "", "unique name"), fs.String("description", "", "description")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.sa.CreateServiceAccount(ctx, &pantherclawv1.CreateServiceAccountRequest{Name: *name, Description: *desc})
			}
		}),
		"sa get": rpc("sa get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.sa.GetServiceAccount(ctx, &pantherclawv1.GetServiceAccountRequest{Id: a[0]})
			}
		}),
		"sa list": rpc("sa list", 0, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.sa.ListServiceAccounts(ctx, &pantherclawv1.ListServiceAccountsRequest{PageSize: size(n), PageToken: *tok})
			}
		}),
		"sa update": rpc("sa update ID --description D", 1, func(fs *flag.FlagSet) call {
			var desc optional
			fs.Var(&desc, "description", "new description")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.sa.UpdateServiceAccount(ctx, &pantherclawv1.UpdateServiceAccountRequest{Id: a[0], Description: desc.ptr()})
			}
		}),
		"sa disable": rpc("sa disable ID", 1, setState(pantherclawv1.AccountState_ACCOUNT_STATE_DISABLED)),
		"sa enable":  rpc("sa enable ID", 1, setState(pantherclawv1.AccountState_ACCOUNT_STATE_ACTIVE)),
		"sa keys": rpc("sa keys SA", 1, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.sa.ListServiceAccountKeys(ctx, &pantherclawv1.ListServiceAccountKeysRequest{ServiceAccountId: a[0], PageSize: size(n), PageToken: *tok})
			}
		}),
		"sa key-add": rpc("sa key-add SA --public-key FILE [--alg EdDSA|ES256] [--ttl-days N]", 1, func(fs *flag.FlagSet) call {
			file, alg, ttl := fs.String("public-key", "", "public JWK file"), fs.String("alg", "EdDSA", "EdDSA or ES256"), fs.Int("ttl-days", 0, "validity (default 90, at most 365)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				ka, ok := keyAlgs[*alg]
				if !ok {
					return nil, errors.New("--alg must be EdDSA or ES256")
				}
				jwk, err := os.ReadFile(*file)
				if err != nil {
					return nil, err
				}
				return c.sa.AddServiceAccountKey(ctx, &pantherclawv1.AddServiceAccountKeyRequest{
					ServiceAccountId: a[0], Algorithm: ka, PublicJwk: string(jwk), TtlDays: days(*ttl),
				})
			}
		}),
		"sa key-generate": {usage: "sa key-generate SA --out FILE [--ttl-days N]", run: keyGenerate},
		"sa key-revoke": rpc("sa key-revoke SA KEY", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.sa.RevokeServiceAccountKey(ctx, &pantherclawv1.RevokeServiceAccountKeyRequest{ServiceAccountId: a[0], KeyId: a[1]})
			}
		}),
		"sa token": {usage: "sa token --key-file FILE [--server URL]", run: saToken},
		"apikey create": rpc("apikey create --sa ID --name NAME --scope PERMISSION... [--ttl-days N]", 0, func(fs *flag.FlagSet) call {
			var scopes list
			sa, name, ttl := fs.String("sa", "", "service account id"), fs.String("name", "", "key name"), fs.Int("ttl-days", 0, "validity (default 90, at most 365)")
			fs.Var(&scopes, "scope", "permission the key may use (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.sa.CreateApiKey(ctx, &pantherclawv1.CreateApiKeyRequest{ServiceAccountId: *sa, Name: *name, Scopes: scopes, TtlDays: days(*ttl)})
			}
		}),
		"apikey list": rpc("apikey list [--sa ID]", 0, func(fs *flag.FlagSet) call {
			sa := fs.String("sa", "", "only this service account")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.sa.ListApiKeys(ctx, &pantherclawv1.ListApiKeysRequest{ServiceAccountId: *sa, PageSize: size(n), PageToken: *tok})
			}
		}),
		"apikey revoke": rpc("apikey revoke ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.sa.RevokeApiKey(ctx, &pantherclawv1.RevokeApiKeyRequest{Id: a[0]})
			}
		}),
	}
}

func days(n int) int32 { return int32(min(max(n, 0), 365)) }

// keyGenerate creates an Ed25519 key pair locally, writes the private key
// (with the client id) to a new 0600 file, and registers only the public
// key. If registration fails, the file is removed.
func keyGenerate(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("sa key-generate", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out, ttl := fs.String("out", "", "private key file to create (must not exist)"), fs.Int("ttl-days", 0, "validity (default 90, at most 365)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	sa, err := c.sa.GetServiceAccount(ctx, &pantherclawv1.GetServiceAccountRequest{Id: args[0]})
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pubJWK, err := jose.JSONWebKey{Key: pub, Algorithm: "EdDSA", Use: "sig"}.MarshalJSON()
	if err != nil {
		return err
	}
	privJWK, err := jose.JSONWebKey{Key: priv, Algorithm: "EdDSA", Use: "sig"}.MarshalJSON()
	if err != nil {
		return err
	}
	body, err := json.Marshal(keyFile{ClientID: sa.GetServiceAccount().GetClientId(), Key: privJWK})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(*out)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	res, err := c.sa.AddServiceAccountKey(ctx, &pantherclawv1.AddServiceAccountKeyRequest{
		ServiceAccountId: args[0], Algorithm: pantherclawv1.KeyAlgorithm_KEY_ALGORITHM_EDDSA, PublicJwk: string(pubJWK), TtlDays: days(*ttl),
	})
	if err != nil {
		_ = os.Remove(*out)
		return err
	}
	_, _ = fmt.Fprintf(a.stderr, "private key written to %s (keep it secret); client id %s\n", *out, sa.GetServiceAccount().GetClientId())
	return a.print(res)
}

// saToken obtains an access token for a service account with a client
// assertion signed by its key file (private_key_jwt), and prints the token
// response.
func saToken(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("sa token", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	file, server := fs.String("key-file", "", "file written by pclaw sa key-generate"), fs.String("server", "", "server URL (default: the logged-in server)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" || fs.NArg() != 0 {
		return errUsage
	}
	if *server == "" {
		c, err := loadCreds(a.env)
		if err != nil {
			return errors.New("give --server or log in first")
		}
		*server = c.Server
	}
	base, err := checkServer(*server)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return fmt.Errorf("%s is not a pclaw key file: %w", *file, err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(kf.Key); err != nil {
		return err
	}
	priv, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return errors.New("the key file does not hold an Ed25519 private key")
	}
	pk, err := publicJWK(priv)
	if err != nil {
		return err
	}
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss": kf.ClientID, "sub": kf.ClientID, "aud": base + tokenPath, "jti": rand.Text(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", pk.Thumbprint))
	if err != nil {
		return err
	}
	obj, err := s.Sign(claims)
	if err != nil {
		return err
	}
	assertion, _ := obj.CompactSerialize()
	var tr tokenResponse
	if err := (oauthClient{server: base, http: a.http}).post(ctx, tokenPath, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {kf.ClientID},
		"client_assertion_type": {assertionType}, "client_assertion": {assertion},
	}, &tr); err != nil {
		return err
	}
	b, _ := json.Marshal(tr, json.Deterministic(true))
	_, err = fmt.Fprintln(a.stdout, string(b))
	return err
}
