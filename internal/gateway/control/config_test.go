// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

const (
	cfgOrg     = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	cfgGateway = "0192aaaa-bbbb-7ccc-8ddd-000000000002"
)

// configServer serves a scripted configuration and counts fetches.
type configServer struct {
	mu      sync.Mutex
	version int64
	fail    bool
	org     string
	raw     []byte
	fetches int
	knowns  []int64
}

func (f *configServer) fetch(_ context.Context, known int64) (*pb.GetConfigurationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	f.knowns = append(f.knowns, known)
	if f.fail {
		return nil, errors.New("server unavailable")
	}
	if known == f.version {
		return &pb.GetConfigurationResponse{Version: f.version, Unchanged: true}, nil
	}
	return &pb.GetConfigurationResponse{
		Version: f.version, OrgId: f.org, GatewayId: cfgGateway,
		Connections: []*pb.GatewayConnection{{
			Id: "c1", Name: "payments", Kind: "http", Package: "pc.mock-payments", PackageVersion: "1.0.0",
			BaseUrl: "https://payments.example.test", DefaultMode: "monitor", State: "ACTIVE",
			Routes: []*pb.RouteModeSetting{{Route: "payments-refund", Mode: "enforce"}},
		}},
		Packages:    []*pb.GatewayPackage{{Name: "pc.mock-payments", Version: "1.0.0", Raw: f.raw}},
		Credentials: []*pb.SealedCredential{{Id: "k1", ConnectionId: "c1", Version: 1}},
	}, nil
}

func (f *configServer) set(fn func(*configServer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *configServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func mockRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestConfigurationIsLoadedBeforeServingAndRefetchedOnChange: the store is
// not ready until a configuration loads; a new version on the stream
// triggers a refetch that sends the known version; the packages are
// decoded and the route modes and credentials indexed.
func TestConfigurationIsLoadedBeforeServingAndRefetchedOnChange(t *testing.T) {
	srv := &configServer{version: 3, org: cfgOrg, raw: mockRaw(t), fail: true}
	s := newStore(srv.fetch, cfgOrg, cfgGateway, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, func() bool { return srv.count() >= 1 })
	select {
	case <-s.Ready():
		t.Fatal("ready without a configuration")
	default:
	}
	srv.set(func(f *configServer) { f.fail = false })
	select {
	case <-s.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("not ready after the server came back")
	}
	c := s.Current()
	p := c.ByName["payments"]
	if c.Version != 3 || p == nil || c.ByID["c1"] != p || p.Package == nil || p.Package.Name != "pc.mock-payments" ||
		p.Mode("payments-refund") != "enforce" || p.Mode("payments-refund-get") != "monitor" || p.Credential.GetId() != "k1" {
		t.Fatalf("configuration %+v", c)
	}
	if d := p.Package.Definitions[0]; d.Digest == "" || d.Dispatch == nil {
		t.Fatal("definitions are not decoded with their digests")
	}

	before := srv.count()
	s.Changed(3) // the version the gateway has: nothing to do
	time.Sleep(50 * time.Millisecond)
	if srv.count() != before {
		t.Fatal("refetched for the version it has")
	}
	srv.set(func(f *configServer) { f.version = 4 })
	s.Changed(4)
	waitFor(t, func() bool { return s.Current().Version == 4 })
	srv.mu.Lock()
	known := srv.knowns[len(srv.knowns)-1]
	srv.mu.Unlock()
	if known != 3 {
		t.Fatalf("the refetch sent known version %d", known)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestAFailedOrRefusedFetchKeepsThePreviousConfiguration: a server error,
// a configuration for another org and an undecodable package each leave
// the loaded configuration in place.
func TestAFailedOrRefusedFetchKeepsThePreviousConfiguration(t *testing.T) {
	srv := &configServer{version: 1, org: cfgOrg, raw: mockRaw(t)}
	s := newStore(srv.fetch, cfgOrg, cfgGateway, nil)
	if err := s.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*configServer){
		"server error":        func(f *configServer) { f.version, f.fail = 2, true },
		"another org":         func(f *configServer) { f.version, f.fail, f.org = 3, false, "0192aaaa-bbbb-7ccc-8ddd-000000000009" },
		"undecodable package": func(f *configServer) { f.version, f.org, f.raw = 4, cfgOrg, []byte("format: 2\n") },
		"another package":     func(f *configServer) { f.version, f.raw = 5, []byte("format: 1\nname: pc.other\n") },
	} {
		srv.set(change)
		if err := s.load(context.Background()); err == nil {
			t.Errorf("%s: loaded", name)
		}
		if c := s.Current(); c.Version != 1 || c.ByName["payments"] == nil {
			t.Fatalf("%s: the previous configuration was replaced: %+v", name, c)
		}
	}
}
