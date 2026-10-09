// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordNotifications struct {
	pantherclawv1connect.UnimplementedNotificationServiceHandler
	create *pantherclawv1.CreateChannelRequest
	update *pantherclawv1.UpdateChannelRequest
	list   *pantherclawv1.ListDeliveriesRequest
}

func (r *recordNotifications) CreateChannel(_ context.Context, req *pantherclawv1.CreateChannelRequest) (*pantherclawv1.CreateChannelResponse, error) {
	r.create = req
	return &pantherclawv1.CreateChannelResponse{Channel: &pantherclawv1.Channel{Name: req.GetName()}, SigningSecret: "whsec_shown_once"}, nil
}

func (r *recordNotifications) UpdateChannel(_ context.Context, req *pantherclawv1.UpdateChannelRequest) (*pantherclawv1.UpdateChannelResponse, error) {
	r.update = req
	return &pantherclawv1.UpdateChannelResponse{Channel: &pantherclawv1.Channel{Id: req.GetId()}}, nil
}

func (r *recordNotifications) ListDeliveries(_ context.Context, req *pantherclawv1.ListDeliveriesRequest) (*pantherclawv1.ListDeliveriesResponse, error) {
	r.list = req
	return &pantherclawv1.ListDeliveriesResponse{}, nil
}

type recordAccount struct {
	pantherclawv1connect.UnimplementedAccountServiceHandler
	remove *pantherclawv1.RemoveUserKeyRequest
}

func (r *recordAccount) RemoveUserKey(_ context.Context, req *pantherclawv1.RemoveUserKeyRequest) (*pantherclawv1.RemoveUserKeyResponse, error) {
	r.remove = req
	return &pantherclawv1.RemoveUserKeyResponse{}, nil
}

func TestM5Commands(t *testing.T) {
	n, acct := &recordNotifications{}, &recordAccount{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterNotificationServiceHandler(cs, n)
	pantherclawv1connect.RegisterAccountServiceHandler(cs, acct)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	// A Slack URL comes from a file, never the command line.
	urlFile := filepath.Join(t.TempDir(), "slack-url")
	if err := os.WriteFile(urlFile, []byte("https://hooks.slack.com/services/T0/B0/X\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, env, "channel", "create", "--name", "chat", "--kind", "slack", "--event", "security.*",
		"--event", "channel.test", "--min-severity", "warning", "--url-file", urlFile)
	if code != 0 || n.create.GetUrl() != "https://hooks.slack.com/services/T0/B0/X" || len(n.create.GetEventTypes()) != 2 ||
		n.create.GetKind() != pantherclawv1.ChannelKind_CHANNEL_KIND_SLACK ||
		n.create.GetMinSeverity() != pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING || !strings.Contains(out, "whsec_shown_once") {
		t.Fatalf("channel create = %d %q %q, request %v", code, out, errs, n.create)
	}
	if code, _, errs := run(t, env, "channel", "create", "--name", "x", "--kind", "sms", "--event", "a.b"); code != 1 || !strings.Contains(errs, "--kind") {
		t.Fatalf("bad kind = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "channel", "update", "0192aaaa-bbbb-7ccc-8ddd-000000000001", "--pause"); code != 0 ||
		n.update.Paused == nil || !*n.update.Paused || n.update.Name != nil || n.update.MinSeverity != nil {
		t.Fatalf("channel update --pause = %d, %v", code, n.update)
	}
	if code, _, errs := run(t, env, "channel", "update", "id", "--pause", "--resume"); code != 1 || !strings.Contains(errs, "not both") {
		t.Fatalf("pause and resume = %d %q", code, errs)
	}
	if code, _, _ := run(t, env, "delivery", "list", "--state", "canceled"); code != 0 ||
		n.list.GetState() != pantherclawv1.DeliveryState_DELIVERY_STATE_CANCELED {
		t.Fatalf("delivery list = %d, %v", code, n.list)
	}
	if code, _, _ := run(t, env, "user", "remove-key", "u1", "k1"); code != 0 || acct.remove.GetUserId() != "u1" || acct.remove.GetKeyId() != "k1" {
		t.Fatalf("user remove-key = %d, %v", code, acct.remove)
	}
	if code, _, _ := run(t, env, "user", "remove-key", "u1"); code != 2 {
		t.Fatalf("missing key = %d", code)
	}
}
