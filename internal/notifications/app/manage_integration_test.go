// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func (e *env) as(kind td.PrincipalKind, id ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}})
}

type edition billingdomain.Edition

func (ed edition) Current(context.Context) (billingdomain.Entitlements, error) {
	return billingdomain.Entitlements{Edition: billingdomain.Edition(ed)}, nil
}

func logChannel(name string) napp.ChannelInput {
	return napp.ChannelInput{Name: name, Kind: domain.KindLog, EventTypes: []string{"security.*"}}
}

func firstPage() page.Request {
	pr, _ := page.Parse(0, "")
	return pr
}

func TestHR157_ChannelAPIChecksPermissionsAndEditionLimits(t *testing.T) {
	e := newEnv(t)
	admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
	auditor := e.as(td.KindUser, e.carol, td.RoleAuditor)
	viewer := e.as(td.KindUser, e.carol, td.RoleViewer)

	if _, _, err := e.svc.CreateChannel(viewer, logChannel("ops")); err == nil {
		t.Fatal("a viewer created a channel")
	}
	if _, _, err := e.svc.CreateChannel(auditor, logChannel("ops")); err == nil {
		t.Fatal("an auditor created a channel")
	}
	for i := range napp.CommunityChannelLimit {
		if _, _, err := e.svc.CreateChannel(admin, logChannel("ops-"+string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.svc.CreateChannel(admin, logChannel("one-too-many")); !errors.Is(err, napp.ErrChannelLimit) {
		t.Fatalf("fourth Community channel: %v", err)
	}
	e.svc.SetEditions(edition(billingdomain.Team))
	if _, _, err := e.svc.CreateChannel(admin, logChannel("team-ok")); err != nil {
		t.Fatalf("Team edition: %v", err)
	}
	if _, _, err := e.svc.CreateChannel(admin, logChannel("team-ok")); !errors.Is(err, napp.ErrChannelNameTaken) {
		t.Errorf("duplicate name: %v", err)
	}
	if _, _, err := e.svc.CreateChannel(admin, napp.ChannelInput{
		Name: "bad", Kind: domain.KindWebhook, EventTypes: []string{"security.*"},
		URL: "https://169.254.169.254/latest",
	}); !errors.Is(err, napp.ErrInvalidURL) {
		t.Errorf("metadata URL: %v", err)
	}
	// Auditors read; listing pages.
	cs, next, err := e.svc.ListChannels(auditor, firstPage())
	if err != nil || len(cs) != 4 || next != "" {
		t.Fatalf("list: %d %q %v", len(cs), next, err)
	}
	if _, _, err := e.svc.ListChannels(viewer, firstPage()); err == nil {
		t.Error("a viewer listed channels")
	}
	// Deleting frees a slot and the name; pending deliveries are canceled.
	e.svc.SetEditions(edition(billingdomain.Community))
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("a")})
	if err := e.svc.DeleteChannel(admin, cs[0].ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.deliveries WHERE channel_id = $1 AND state = 'CANCELLED'", cs[0].ID); n != 1 {
		t.Errorf("%d canceled deliveries, want 1", n)
	}
	if _, _, err := e.svc.GetChannel(admin, cs[0].ID); !errors.Is(err, napp.ErrChannelNotFound) {
		t.Errorf("deleted channel: %v", err)
	}
	if _, _, err := e.svc.CreateChannel(admin, logChannel(cs[0].Name)); !errors.Is(err, napp.ErrChannelLimit) {
		t.Errorf("still 4 live channels after deleting one in Community: %v", err)
	}
	// IDOR: another org's admin sees nothing.
	other := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: ids.New[ids.Org](), Principal: td.PrincipalRef{Kind: td.KindUser, ID: e.alice},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: ids.NewV7()}}},
	}})
	if _, _, err := e.svc.GetChannel(other, cs[1].ID); err == nil {
		t.Error("another org read the channel")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.notification.channel_created'"); n != 4 {
		t.Errorf("%d creation audit events, want 4", n)
	}
}

func TestHR159_ChannelsCanBePausedTestedAndRotated(t *testing.T) {
	r := newReceiver(t)
	e := webhookEnv(t, r)
	admin := e.as(td.KindUser, e.alice, td.RoleOrgAdmin)
	hook, secret, err := e.svc.CreateChannel(admin, napp.ChannelInput{
		Name: "siem", Kind: domain.KindWebhook,
		EventTypes: []string{"security.*"}, URL: r.URL + "/pc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hook.URL == "" || secret == "" {
		t.Fatal("webhook URL or secret missing")
	}
	other, _, err := e.svc.CreateChannel(admin, logChannel("ops"))
	if err != nil {
		t.Fatal(err)
	}
	// A test goes to that channel only, whatever its subscription.
	note, err := e.svc.TestChannel(admin, hook.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.deliveries WHERE notification_id = $1", note); n != 1 {
		t.Fatalf("test notification has %d deliveries, want 1", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.deliveries WHERE channel_id = $1", other.ID); n != 0 {
		t.Fatal("the test reached another channel")
	}
	if err := e.svc.Deliver(context.Background(), e.org, e.delivery(t)); err != nil {
		t.Fatal(err)
	}
	// Rotation: the new secret is shown once, and both secrets sign for 24 hours.
	newSecret, until, err := e.svc.RotateChannelSecret(admin, hook.ID)
	if err != nil || newSecret == secret || time.Until(until) < 23*time.Hour {
		t.Fatalf("rotate: %v until %s", err, until)
	}
	e.enqueue(t, napp.Message{Type: "security.credential_registered", Params: registered("a")})
	if err := e.svc.Deliver(context.Background(), e.org, e.delivery(t)); err != nil {
		t.Fatal(err)
	}
	last := r.got()[len(r.got())-1]
	if !verify(t, secret, last.header, last.body) || !verify(t, newSecret, last.header, last.body) {
		t.Fatal("during the overlap both the old and the new secret must verify")
	}
	if _, _, err := e.svc.RotateChannelSecret(admin, other.ID); !errors.Is(err, napp.ErrNotAWebhook) {
		t.Errorf("rotating a log channel: %v", err)
	}
	// Pause and resume; a paused channel skips, a resumed one is healthy.
	paused := true
	c, err := e.svc.UpdateChannel(admin, hook.ID, napp.ChannelUpdate{Paused: &paused})
	if err != nil || c.State != "PAUSED" || c.PauseReason != "MANUAL" {
		t.Fatalf("pause: %+v %v", c, err)
	}
	paused = false
	name := "siem-2"
	if c, err = e.svc.UpdateChannel(admin, hook.ID, napp.ChannelUpdate{Paused: &paused, Name: &name}); err != nil || c.State != "ACTIVE" || c.Name != "siem-2" {
		t.Fatalf("resume: %+v %v", c, err)
	}
	if _, err := e.svc.UpdateChannel(admin, hook.ID, napp.ChannelUpdate{EventTypes: []string{"*"}}); !errors.Is(err, napp.ErrInvalidChannel) {
		t.Errorf("subscribe to everything: %v", err)
	}
	ch, recent, err := e.svc.GetChannel(admin, hook.ID)
	if err != nil || len(recent) != 2 || ch.Health != domain.Healthy || ch.PreviousSecretExpiry == nil {
		t.Fatalf("get: %+v, %d recent, %v", ch, len(recent), err)
	}
	ds, _, err := e.svc.ListDeliveries(admin, napp.DeliveryFilter{Channel: &hook.ID, State: "DELIVERED"}, firstPage())
	if err != nil || len(ds) != 2 || !ds[0].CreatedAt.After(ds[1].CreatedAt) && ds[0].CreatedAt != ds[1].CreatedAt {
		t.Fatalf("deliveries: %d %v", len(ds), err)
	}
}
