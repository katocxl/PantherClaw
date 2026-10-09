// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

func newCA(t *testing.T) *ca.Authority {
	t.Helper()
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeGatewayCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	a, err := ca.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fakeServer is a GatewayService that issues certificates from a CA. It
// can hand out another CA or a certificate naming another gateway, to test
// what the gateway accepts.
type fakeServer struct {
	pantherclawv1connect.UnimplementedGatewayServiceHandler
	ca      *ca.Authority
	rogueCA *ca.Authority
	id      ca.Identity

	mu        sync.Mutex
	wrongCA   bool
	otherGW   bool
	wrongKey  bool
	renewals  int
	presented [][]byte // client certificates seen by renewals
}

func (f *fakeServer) issue(csr []byte) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pub, err := ca.ParseRequest(csr)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
	}
	if f.wrongKey {
		pub, _, _ = ed25519.GenerateKey(rand.Reader)
	}
	id := f.id
	id.Cert = ids.NewV7()
	if f.otherGW {
		id.Gateway = ids.NewV7()
	}
	issuer := f.ca
	if f.wrongCA {
		issuer = f.rogueCA
	}
	iss, err := issuer.IssueClient(pub, id, time.Now())
	if err != nil {
		return nil, nil, err
	}
	return iss.DER, issuer.Certificate(), nil
}

func (f *fakeServer) Enroll(_ context.Context, req *pb.GatewayServiceEnrollRequest) (*pb.GatewayServiceEnrollResponse, error) {
	cert, caDER, err := f.issue(req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &pb.GatewayServiceEnrollResponse{
		Certificate: cert, CaCertificate: caDER, GatewayId: f.id.Gateway.String(),
		OrgId: f.id.Org.String(), GatewayApiUrl: "https://gateways.invalid",
	}, nil
}

func (f *fakeServer) RenewCertificate(ctx context.Context, req *pb.RenewCertificateRequest) (*pb.RenewCertificateResponse, error) {
	f.mu.Lock()
	f.renewals++
	if peer, ok := ctx.Value(peerKey{}).([]byte); ok {
		f.presented = append(f.presented, peer)
	}
	f.mu.Unlock()
	cert, caDER, err := f.issue(req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &pb.RenewCertificateResponse{Certificate: cert, CaCertificate: caDER}, nil
}

type peerKey struct{}

// start serves the fake over plain HTTP (enrollment) and mutual TLS
// (renewal), requiring a client certificate from the CA on the latter.
func start(t *testing.T) (*fakeServer, string, string) {
	t.Helper()
	f := &fakeServer{ca: newCA(t), rogueCA: newCA(t), id: ca.Identity{Org: ids.New[ids.Org](), Gateway: ids.NewV7()}}
	s, err := rpc.NewServer(rpc.Options{Logger: pclog.Discard(), Authenticate: func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		return ctx, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterGatewayServiceHandler(s, f)
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	withPeer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, r.TLS.PeerCertificates[0].Raw))
		}
		mux.ServeHTTP(w, r)
	})
	plain := httptest.NewServer(withPeer)
	t.Cleanup(plain.Close)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srvCert, err := f.ca.IssueServer(pub, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: withPeer, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.DER}, PrivateKey: priv}},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.ca.Pool(),
	}}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return f, plain.URL, "https://" + ln.Addr().String()
}

func enroll(t *testing.T, apiURL, pin string) (*Identity, error) {
	t.Helper()
	return Enroll(context.Background(), &http.Client{Timeout: 5 * time.Second}, apiURL, pclog.NewSecret("pcg_test_token_for_unit_tests"), pin)
}

// TestHR180_TheGatewayPinsTheCAAtEnrollment: the gateway accepts only the
// CA whose SHA-256 is its pin, and only a certificate for its own key.
func TestHR180_TheGatewayPinsTheCAAtEnrollment(t *testing.T) {
	f, apiURL, _ := start(t)
	pin := ca.Fingerprint(f.ca.Certificate())
	id, err := enroll(t, apiURL, pin)
	if err != nil {
		t.Fatal(err)
	}
	if id.Org != f.id.Org || id.Gateway != f.id.Gateway || id.CASHA256 != pin {
		t.Fatalf("identity %+v", id)
	}
	f.wrongCA = true
	if _, err := enroll(t, apiURL, pin); !errors.Is(err, ErrPin) {
		t.Fatalf("another CA at enrollment: %v", err)
	}
	f.wrongCA, f.wrongKey = false, true
	if _, err := enroll(t, apiURL, pin); !errors.Is(err, ErrIdentity) {
		t.Fatalf("a certificate for another key: %v", err)
	}
}

func TestIdentityIsSavedPrivatelyAndCheckedOnLoad(t *testing.T) {
	f, apiURL, _ := start(t)
	pin := ca.Fingerprint(f.ca.Certificate())
	id, err := enroll(t, apiURL, pin)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "identity")
	if _, err := Load(dir, pin); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("empty directory: %v", err)
	}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir, "")
	if err != nil || got.Cert != id.Cert || got.Gateway != id.Gateway {
		t.Fatalf("load: %+v %v", got, err)
	}
	if _, err := Load(dir, ca.Fingerprint(f.rogueCA.Certificate())); !errors.Is(err, ErrPin) {
		t.Fatalf("load with another pin: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, identityFile)); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("identity file mode: %v %v", fi, err)
	}
}

// TestHR180_RenewalSwitchesCertificatesAndKeepsTheGateway: renewal goes
// over mTLS with the current certificate, new connections then present the
// new one, and a renewal naming another gateway or CA is refused.
func TestHR180_RenewalSwitchesCertificatesAndKeepsTheGateway(t *testing.T) {
	f, apiURL, mtlsURL := start(t)
	pin := ca.Fingerprint(f.ca.Certificate())
	id, err := enroll(t, apiURL, pin)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c := NewClient(id, dir, mtlsURL, 5*time.Second, pclog.Discard())
	ctx := context.Background()
	if err := c.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	first := c.Identity()
	if first.Cert == id.Cert || first.Gateway != id.Gateway {
		t.Fatalf("renewed identity %+v", first)
	}
	c.HTTPClient().CloseIdleConnections()
	if err := c.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.presented) != 2 {
		t.Fatalf("%d renewals saw a client certificate", len(f.presented))
	}
	seen, _ := x509.ParseCertificate(f.presented[1])
	if got, _ := ca.ParseIdentity(seen); got.Cert != first.Cert {
		t.Fatal("the second renewal did not present the renewed certificate")
	}
	if saved, err := Load(dir, pin); err != nil || saved.Cert != c.Identity().Cert {
		t.Fatalf("the renewed identity was not saved: %v", err)
	}
	f.otherGW = true
	if err := c.Renew(ctx); !errors.Is(err, ErrIdentity) {
		t.Fatalf("a renewal naming another gateway: %v", err)
	}
	f.otherGW, f.wrongCA = false, true
	if err := c.Renew(ctx); err == nil {
		t.Fatal("a renewal from another CA was accepted")
	}
}

// TestHR074_TheControlClientTrustsOnlyTheInternalCA: the mTLS client
// refuses a server whose certificate is not from the pinned CA.
func TestHR074_TheControlClientTrustsOnlyTheInternalCA(t *testing.T) {
	f, apiURL, _ := start(t)
	id, err := enroll(t, apiURL, ca.Fingerprint(f.ca.Certificate()))
	if err != nil {
		t.Fatal(err)
	}
	other := httptest.NewTLSServer(http.NotFoundHandler()) // a public-looking server with its own CA
	t.Cleanup(other.Close)
	c := NewClient(id, "", other.URL, 2*time.Second, pclog.Discard())
	if _, err := c.Gateway.RenewCertificate(context.Background(), &pb.RenewCertificateRequest{Csr: []byte("x")}); err == nil {
		t.Fatal("the control client trusted a server outside the internal CA")
	}
}
