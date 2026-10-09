// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
)

// Credential commands (G0 M6 design decision 8, HR-060, HR-182). pclaw seal
// encrypts a target credential on this machine to the broker key of the
// connection's gateway and uploads only the sealed bytes: the plaintext
// never leaves the machine, never reaches PantherClaw's server and is never
// printed.

// maxCredential bounds a credential file.
const maxCredential = 64 << 10

func init() {
	commands["seal"] = command{
		usage: "seal --connection ID --from-file FILE [--fingerprint sha256:HEX]",
		run:   seal,
	}
	commands["credential list"] = rpc("credential list CONNECTION", 1, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			return c.connections.ListCredentials(ctx, &pb.ListCredentialsRequest{ConnectionId: a[0]})
		}
	})
	commands["credential revoke"] = rpc("credential revoke CONNECTION VERSION", 2, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			var v int32
			if _, err := fmt.Sscanf(a[1], "%d", &v); err != nil || v <= 0 {
				return nil, errors.New("VERSION is a positive number")
			}
			return c.connections.RevokeCredential(ctx, &pb.RevokeCredentialRequest{ConnectionId: a[0], Version: v})
		}
	})
}

// readCredential reads a credential file: at most 64 KiB, with one trailing
// line break removed (editors add one).
func readCredential(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCredential+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCredential {
		return nil, fmt.Errorf("the credential file is larger than %d bytes", maxCredential)
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) == 0 {
		return nil, errors.New("the credential file is empty")
	}
	return b, nil
}

func seal(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	conn := fs.String("connection", "", "connection id")
	from := fs.String("from-file", "", "file holding the credential (never pass it on the command line)")
	expect := fs.String("fingerprint", "", "the broker key fingerprint the gateway's operator gave you; sealing stops if it differs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *conn == "" || *from == "" {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	k, err := c.connections.GetSealingKey(ctx, &pb.GetSealingKeyRequest{ConnectionId: *conn})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(k.GetPublicKey())
	fp := "sha256:" + hex.EncodeToString(sum[:])
	if fp != k.GetFingerprint() {
		return errors.New("the server's broker key does not match its fingerprint; nothing was sealed")
	}
	if *expect != "" && !strings.EqualFold(*expect, fp) {
		return fmt.Errorf("the broker key is %s, not the expected %s; nothing was sealed", fp, *expect)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.GetPublicKey())
	if err != nil {
		return fmt.Errorf("the broker key is not an X-Wing key: %w", err)
	}
	_, _ = fmt.Fprintf(a.stderr, "Sealing version %d for connection %s to broker key %s of gateway %s.\n"+
		"It will be sent only to %s, in the %s header%s.\n",
		k.GetVersion(), k.GetConnectionId(), fp, k.GetGatewayId(), strings.Join(k.GetAllowedHosts(), ", "), k.GetHeader(),
		map[bool]string{true: " with scheme " + k.GetScheme(), false: ""}[k.GetScheme() != ""])
	secret, err := readCredential(*from)
	if err != nil {
		return err
	}
	b := domain.Binding{
		Org: k.GetOrgId(), Connection: k.GetConnectionId(), Version: k.GetVersion(), AllowedHosts: k.GetAllowedHosts(),
		BrokerKey: k.GetBrokerKeyId(), Header: k.GetHeader(), Scheme: k.GetScheme(),
	}
	sealed, err := pccrypto.Seal(pub, b.Info(), domain.AAD, secret)
	clear(secret)
	if err != nil {
		return err
	}
	res, err := c.connections.PutCredential(ctx, &pb.PutCredentialRequest{
		ConnectionId: k.GetConnectionId(), Version: k.GetVersion(), BrokerKeyId: k.GetBrokerKeyId(), Sealed: sealed,
		AllowedHosts: k.GetAllowedHosts(), Header: k.GetHeader(), Scheme: k.GetScheme(),
	})
	if err != nil {
		return err
	}
	return a.print(res)
}
