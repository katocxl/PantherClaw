// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// Org package-signing keys (HR-162, ADR-0020; Team edition). The private
// key is created and used only on this machine: create writes it to a file
// (encrypted with a passphrase when one is given), register sends only the
// public half, and sign signs targets offline. Nothing here sends a private
// key anywhere.

func init() {
	for k, v := range packageKeyCommands() {
		commands[k] = v
	}
}

var revokeReasons = map[string]pantherclawv1.SigningKeyRevokeReason{
	"rotated":     pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_ROTATED,
	"compromised": pantherclawv1.SigningKeyRevokeReason_SIGNING_KEY_REVOKE_REASON_COMPROMISED,
}

// keyRPC is rpc for PackageService, whose client this file builds itself.
func keyRPC(usage string, nargs int, setup func(fs *flag.FlagSet) func(context.Context, pantherclawv1connect.PackageServiceClient, []string) (proto.Message, error)) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewPackageServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return err
		}
		return a.print(res)
	}}
}

func packageKeyCommands() map[string]command {
	type pkgCall = func(context.Context, pantherclawv1connect.PackageServiceClient, []string) (proto.Message, error)
	return map[string]command{
		"package-key create": {"package-key create --name NAME --out-dir DIR [--passphrase-file FILE]", createPackageKey},
		"package-key register": keyRPC("package-key register --name NAME --public-key-file FILE", 0, func(fs *flag.FlagSet) pkgCall {
			name, file := fs.String("name", "", "a name for people"), fs.String("public-key-file", "", "the .pub.json file from package-key create")
			return func(ctx context.Context, c pantherclawv1connect.PackageServiceClient, _ []string) (proto.Message, error) {
				if *name == "" || *file == "" {
					return nil, errUsage
				}
				b, err := os.ReadFile(*file)
				if err != nil {
					return nil, err
				}
				return c.RegisterSigningKey(ctx, &pantherclawv1.RegisterSigningKeyRequest{Name: *name, PublicJwk: strings.TrimSpace(string(b))})
			}
		}),
		"package-key revoke": keyRPC("package-key revoke KID --reason rotated|compromised", 1, func(fs *flag.FlagSet) pkgCall {
			reason := fs.String("reason", "", "rotated (keep what it signed) or compromised (withdraw what it signed)")
			return func(ctx context.Context, c pantherclawv1connect.PackageServiceClient, a []string) (proto.Message, error) {
				r, ok := revokeReasons[*reason]
				if !ok {
					return nil, errors.New("--reason must be rotated or compromised")
				}
				return c.RevokeSigningKey(ctx, &pantherclawv1.RevokeSigningKeyRequest{Kid: a[0], Reason: r})
			}
		}),
		"package-key list": keyRPC("package-key list", 0, func(*flag.FlagSet) pkgCall {
			return func(ctx context.Context, c pantherclawv1connect.PackageServiceClient, _ []string) (proto.Message, error) {
				return c.ListSigningKeys(ctx, &pantherclawv1.ListSigningKeysRequest{})
			}
		}),
		"package sign": {"package sign --key FILE [--passphrase-file FILE] --version N --expires-days D --out FILE PACKAGE.yaml...", signOrgPackages},
	}
}

// maxExpiryDays bounds --expires-days, as in pclaw-admin: signed targets
// stay valid until they expire, so a typo must not sign one for years.
const maxExpiryDays = 365

// keyFileName is the --name of package-key create: a plain file name.
var keyFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func readPassphrase(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	s, err := config.ReadSecretFile(path)
	if err != nil {
		return nil, err
	}
	return s.Reveal(), nil
}

// createPackageKey generates an org package-signing key on this machine.
func createPackageKey(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("package-key create", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	name := fs.String("name", "", "file name for the key (letters, digits, dots, dashes, underscores)")
	outDir := fs.String("out-dir", "", "directory for the key files")
	ppFile := fs.String("passphrase-file", "", fmt.Sprintf("file holding a passphrase (at least %d characters) to encrypt the private key", rootkey.MinPassphrase))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outDir == "" || !keyFileName.MatchString(*name) || fs.NArg() != 0 {
		return errUsage
	}
	pp, err := readPassphrase(*ppFile)
	if err != nil {
		return err
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposeOrgPackages)
	if err != nil {
		return err
	}
	privPEM, err := rootkey.Encode(rootkey.PurposeOrgPackages, priv, pp)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, kid))
	if err != nil {
		return err
	}
	privPath, pubPath := filepath.Join(*outDir, *name+".key"), filepath.Join(*outDir, *name+".pub.json")
	if err := rootkey.WriteNew(privPath, privPEM); err != nil {
		return err
	}
	if err := rootkey.WriteNew(pubPath, append(jwk, '\n')); err != nil {
		return err
	}
	encrypted := "UNENCRYPTED: keep it on encrypted storage"
	if len(pp) > 0 {
		encrypted = "encrypted with your passphrase"
	}
	_, _ = fmt.Fprintf(a.stdout, "Created package-signing key %s\n  private key: %s (%s)\n  public key:  %s\n\n", kid, privPath, encrypted, pubPath)
	_, _ = fmt.Fprintf(a.stdout, "Keep the private key off servers and out of the repository. Register the public key with:\n  pclaw package-key register --name NAME --public-key-file %s\n", pubPath)
	return nil
}

// signOrgPackages signs targets listing the exact bytes of each package
// file with an org package-signing key, offline.
func signOrgPackages(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("package sign", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	keyFile := fs.String("key", "", "org package-signing private key file (package-key create)")
	ppFile := fs.String("passphrase-file", "", "passphrase file for an encrypted key")
	version := fs.Int64("version", 0, "targets version, higher than the last one this key signed")
	days := fs.Int("expires-days", 0, fmt.Sprintf("days until the targets expire, 1..%d", maxExpiryDays))
	out := fs.String("out", "", "output targets file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *version < 1 || *days < 1 || *days > maxExpiryDays || *out == "" || fs.NArg() == 0 {
		return errUsage
	}
	pp, err := readPassphrase(*ppFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	p, priv, err := rootkey.Decode(keyPEM, pp)
	if err != nil {
		return err
	}
	if p != rootkey.PurposeOrgPackages {
		return fmt.Errorf("%s is a %s key, not an org package-signing key", *keyFile, p)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	signer, err := jws.NewSigner(trust.OrgKID(pub), priv)
	if err != nil {
		return err
	}
	t := trust.Targets{
		Version: *version,
		Expires: time.Now().UTC().Truncate(time.Second).AddDate(0, 0, *days).Format(time.RFC3339),
		Targets: map[string]trust.Target{},
	}
	var listed []string
	for _, path := range fs.Args() {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: user-chosen package file
		if err != nil {
			return err
		}
		key, tg, err := trust.TargetOf(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, dup := t.Targets[key]; dup {
			return fmt.Errorf("%s: %s is listed twice", path, key)
		}
		t.Targets[key] = tg
		listed = append(listed, fmt.Sprintf("  %s  %d bytes  (%s)\n", key, tg.Length, path))
	}
	doc, err := trust.Sign(t, signer)
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(*out, []byte(doc+"\n")); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stdout, "Signed package targets version %d with %s, expires %s → %s\n", t.Version, signer.KeyID(), t.Expires, *out)
	for _, l := range listed {
		_, _ = fmt.Fprint(a.stdout, l)
	}
	_, _ = fmt.Fprintf(a.stdout, "Import each package with pclaw package import; sign the next targets with --version %d or higher.\n", t.Version+1)
	return nil
}
