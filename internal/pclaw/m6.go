// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// M6 commands: gateways and the kill switch. The kill switch is engaged and
// restored only on the emergency-stop page (G0 M6 decision 2, HR-113):
// `killswitch status` shows it and prints the page link.

func init() {
	for k, v := range gatewayCommands() {
		commands[k] = v
	}
	commands["killswitch status"] = command{usage: "killswitch status", run: killSwitchStatus}
}

func gatewayCommands() map[string]command {
	return map[string]command{
		"gateway create": rpc("gateway create NAME", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.gateways.CreateGateway(ctx, &pantherclawv1.CreateGatewayRequest{Name: a[0]})
			}
		}),
		"gateway list": rpc("gateway list [--include-revoked]", 0, func(fs *flag.FlagSet) call {
			revoked := fs.Bool("include-revoked", false, "also list revoked gateways")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.gateways.ListGateways(ctx, &pantherclawv1.ListGatewaysRequest{PageSize: size(n), PageToken: *tok, IncludeRevoked: *revoked})
			}
		}),
		"gateway get": rpc("gateway get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.gateways.GetGateway(ctx, &pantherclawv1.GetGatewayRequest{Id: a[0]})
			}
		}),
		// The token is shown once: put it in the gateway's enrollment file.
		"gateway enroll-token": rpc("gateway enroll-token ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.gateways.CreateGatewayEnrollmentToken(ctx, &pantherclawv1.CreateGatewayEnrollmentTokenRequest{GatewayId: a[0]})
			}
		}),
		"gateway revoke": rpc("gateway revoke ID --reason TEXT", 1, func(fs *flag.FlagSet) call {
			reason := fs.String("reason", "", "why (recorded in the ledger)")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.gateways.RevokeGateway(ctx, &pantherclawv1.RevokeGatewayRequest{Id: a[0], Reason: *reason})
			}
		}),
		"gateway revoke-cert": rpc("gateway revoke-cert GATEWAY CERT", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.gateways.RevokeGatewayCertificate(ctx, &pantherclawv1.RevokeGatewayCertificateRequest{GatewayId: a[0], CertificateId: a[1]})
			}
		}),
	}
}

// killSwitchStatus prints the kill switch and, on stderr, where to engage
// or restore it.
func killSwitchStatus(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := c.containment.GetKillSwitch(ctx, &pantherclawv1.GetKillSwitchRequest{})
	if err != nil {
		return err
	}
	if err := a.print(res); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.stderr, "Engage or restore the kill switch on the emergency-stop page: %s\n", res.GetPageUrl())
	return err
}

// m6Clients are the M6 service clients.
type m6Clients struct {
	gateways    pantherclawv1connect.GatewayAdminServiceClient
	containment pantherclawv1connect.ContainmentServiceClient
}
