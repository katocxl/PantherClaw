// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// M5 part 1 commands: one's own sessions and keys, their administration,
// and notification channels. Security keys are added on the account page
// in a browser (WebAuthn needs the browser).

var (
	channelKinds = map[string]pantherclawv1.ChannelKind{
		"log": pantherclawv1.ChannelKind_CHANNEL_KIND_LOG, "email": pantherclawv1.ChannelKind_CHANNEL_KIND_EMAIL,
		"slack": pantherclawv1.ChannelKind_CHANNEL_KIND_SLACK, "webhook": pantherclawv1.ChannelKind_CHANNEL_KIND_WEBHOOK,
	}
	severityNames = map[string]pantherclawv1.NotificationSeverity{
		"info":     pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_INFO,
		"warning":  pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING,
		"critical": pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_CRITICAL,
	}
	deliveryStateNames = map[string]pantherclawv1.DeliveryState{
		"pending": pantherclawv1.DeliveryState_DELIVERY_STATE_PENDING, "delivered": pantherclawv1.DeliveryState_DELIVERY_STATE_DELIVERED,
		"failed": pantherclawv1.DeliveryState_DELIVERY_STATE_FAILED, "expired": pantherclawv1.DeliveryState_DELIVERY_STATE_EXPIRED,
		"skipped": pantherclawv1.DeliveryState_DELIVERY_STATE_SKIPPED, "dropped": pantherclawv1.DeliveryState_DELIVERY_STATE_DROPPED,
		"canceled": pantherclawv1.DeliveryState_DELIVERY_STATE_CANCELED,
	}
)

func init() {
	for k, v := range accountCommands() {
		commands[k] = v
	}
	for k, v := range notificationCommands() {
		commands[k] = v
	}
}

func accountCommands() map[string]command {
	return map[string]command{
		"session list": rpc("session list", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.account.ListMySessions(ctx, &pantherclawv1.ListMySessionsRequest{})
			}
		}),
		"session revoke": rpc("session revoke ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.account.RevokeMySession(ctx, &pantherclawv1.RevokeMySessionRequest{Id: a[0]})
			}
		}),
		"key list": rpc("key list", 0, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.account.ListMyKeys(ctx, &pantherclawv1.ListMyKeysRequest{})
			}
		}),
		"user sessions": rpc("user sessions USER", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.account.ListUserSessions(ctx, &pantherclawv1.ListUserSessionsRequest{UserId: a[0]})
			}
		}),
		"user revoke-sessions": rpc("user revoke-sessions USER", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.account.RevokeUserSessions(ctx, &pantherclawv1.RevokeUserSessionsRequest{UserId: a[0]})
			}
		}),
		"user keys": rpc("user keys USER", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.account.ListUserKeys(ctx, &pantherclawv1.ListUserKeysRequest{UserId: a[0]})
			}
		}),
		"user remove-key": rpc("user remove-key USER KEY", 2, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.account.RemoveUserKey(ctx, &pantherclawv1.RemoveUserKeyRequest{UserId: a[0], KeyId: a[1]})
			}
		}),
	}
}

// readURLFile reads a destination URL from a file, so a Slack webhook URL
// (a secret) never appears in shell history or the process list.
func readURLFile(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func notificationCommands() map[string]command {
	return map[string]command{
		"channel create": rpc("channel create --name NAME --kind log|email|slack|webhook --event TYPE... [--min-severity info|warning|critical] "+
			"[--role ROLE] [--url URL | --url-file FILE]", 0, func(fs *flag.FlagSet) call {
			var events list
			name, kind := fs.String("name", "", "channel name"), fs.String("kind", "", "log, email, slack or webhook")
			sev, role := fs.String("min-severity", "info", "lowest severity delivered"), fs.String("role", "", "email: role whose holders receive it")
			u, uf := fs.String("url", "", "webhook endpoint (https)"), fs.String("url-file", "", "file holding the URL (use it for Slack: the URL is a secret)")
			fs.Var(&events, "event", "event type or prefix.* (repeatable)")
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				k, ok := channelKinds[*kind]
				if !ok {
					return nil, errors.New("--kind must be log, email, slack or webhook")
				}
				s, ok := severityNames[*sev]
				if !ok {
					return nil, errors.New("--min-severity must be info, warning or critical")
				}
				dest := *u
				if *uf != "" {
					var err error
					if dest, err = readURLFile(*uf); err != nil {
						return nil, err
					}
				}
				return c.notifications.CreateChannel(ctx, &pantherclawv1.CreateChannelRequest{
					Name: *name, Kind: k, EventTypes: events, MinSeverity: s, RecipientRole: *role, Url: dest,
				})
			}
		}),
		"channel list": rpc("channel list", 0, func(fs *flag.FlagSet) call {
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				return c.notifications.ListChannels(ctx, &pantherclawv1.ListChannelsRequest{PageSize: size(n), PageToken: *tok})
			}
		}),
		"channel get": rpc("channel get ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.notifications.GetChannel(ctx, &pantherclawv1.GetChannelRequest{Id: a[0]})
			}
		}),
		"channel update": rpc("channel update ID [--name NAME] [--event TYPE...] [--min-severity S] [--pause | --resume]", 1, func(fs *flag.FlagSet) call {
			var events list
			var name, sev optional
			fs.Var(&name, "name", "new name")
			fs.Var(&sev, "min-severity", "info, warning or critical")
			fs.Var(&events, "event", "new subscription (repeatable; replaces the old one)")
			pause, resume := fs.Bool("pause", false, "pause the channel"), fs.Bool("resume", false, "resume the channel")
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				req := &pantherclawv1.UpdateChannelRequest{Id: a[0], Name: name.ptr(), EventTypes: events}
				if sev.set {
					s, ok := severityNames[sev.v]
					if !ok {
						return nil, errors.New("--min-severity must be info, warning or critical")
					}
					req.MinSeverity = &s
				}
				switch {
				case *pause && *resume:
					return nil, errors.New("use --pause or --resume, not both")
				case *pause:
					req.Paused = proto.Bool(true)
				case *resume:
					req.Paused = proto.Bool(false)
				}
				return c.notifications.UpdateChannel(ctx, req)
			}
		}),
		"channel delete": rpc("channel delete ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.notifications.DeleteChannel(ctx, &pantherclawv1.DeleteChannelRequest{Id: a[0]})
			}
		}),
		"channel rotate-secret": rpc("channel rotate-secret ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.notifications.RotateChannelSecret(ctx, &pantherclawv1.RotateChannelSecretRequest{Id: a[0]})
			}
		}),
		"channel test": rpc("channel test ID", 1, func(*flag.FlagSet) call {
			return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
				return c.notifications.TestChannel(ctx, &pantherclawv1.TestChannelRequest{Id: a[0]})
			}
		}),
		"delivery list": rpc("delivery list [--channel ID] [--state pending|delivered|failed|expired|skipped|dropped|canceled]", 0, func(fs *flag.FlagSet) call {
			ch, st := fs.String("channel", "", "only this channel"), fs.String("state", "", "only this state")
			n, tok := paging(fs)
			return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
				req := &pantherclawv1.ListDeliveriesRequest{ChannelId: *ch, PageSize: size(n), PageToken: *tok}
				if *st != "" {
					s, ok := deliveryStateNames[*st]
					if !ok {
						return nil, errors.New("--state must be pending, delivered, failed, expired, skipped, dropped or canceled")
					}
					req.State = s
				}
				return c.notifications.ListDeliveries(ctx, req)
			}
		}),
	}
}
