// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
)

// PAP/1 request headers (PAP-1 §4, §5). The run and action ids are what the
// workload says; the Authority checks the run against the verified
// instance (HR-022).
const (
	HeaderProof    = "PAP-Proof"
	HeaderNonce    = "PAP-Nonce"
	HeaderError    = "PAP-Error"
	HeaderRunID    = "PAP-Run-Id"
	HeaderActionID = "PC-Action-Id"
)

// nonces caches the org's current nonce from Authority responses (G0 M3
// constraint 7).
type nonces struct {
	mu  sync.Mutex
	cur string
}

func (n *nonces) set(v string) {
	if v == "" {
		return
	}
	n.mu.Lock()
	n.cur = v
	n.mu.Unlock()
}

func (n *nonces) get() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cur
}

// nonce returns the cached nonce, asking the Authority when there is none.
func (g *Gateway) nonce(ctx context.Context) string {
	if v := g.nonces.get(); v != "" {
		return v
	}
	if res, err := g.authority.GetNonce(ctx, &pb.GetNonceRequest{}); err == nil {
		g.nonces.set(res.GetNonce())
	}
	return g.nonces.get()
}

// refusePAP answers 401 with a PAP-Error code and a nonce (PAP-1 §12).
func (g *Gateway) refusePAP(ctx context.Context, w http.ResponseWriter, code pap.Code, nonce string) {
	if nonce == "" {
		nonce = g.nonce(ctx)
	}
	if nonce != "" {
		w.Header().Set(HeaderNonce, nonce)
	}
	w.Header().Set(HeaderError, string(code))
	reply(w, http.StatusUnauthorized, result{Error: string(code)})
}

// tokenSubject reads, WITHOUT verifying, the instance and environment a
// workload token names, to put them in the ActionIR. The Authority verifies
// the token and refuses an action whose instance or environment differs
// (IDENTITY_MISMATCH).
func tokenSubject(token string) (instance, env string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 8192 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	var c struct {
		Sub string `json:"sub"`
		PAP struct {
			Env string `json:"env"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return "", "", false
	}
	id, err := pap.ParseInstance(c.Sub)
	if err != nil || c.PAP.Env == "" {
		return "", "", false
	}
	return id.Instance.String(), c.PAP.Env, true
}

// reportUnknown reports a key-only request to the Authority (HR-148) and
// refuses it.
func (g *Gateway) reportUnknown(ctx context.Context, w http.ResponseWriter, r *http.Request, creds *pb.WorkloadCredentials) {
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	res, err := g.authority.ReportUnknownWorkload(ctx, &pb.ReportUnknownWorkloadRequest{
		Workload: creds, UserAgent: strings.ToValidUTF8(ua, ""), Route: "payments-refund",
	})
	code := pap.CodeInstanceNotAdmitted
	if err != nil {
		// A report whose proof does not verify carries its PAP-Error code.
		var ce *connect.Error
		if errors.As(err, &ce) {
			if c, ok := strings.CutPrefix(ce.Message(), "PAP/1: "); ok {
				code = pap.Code(c)
			}
		}
	}
	g.refusePAP(ctx, w, code, res.GetNonce())
}

// clientAddress is the workload's address as the gateway saw it. It is
// UNTRUSTED and only feeds the network-change alert (HR-092).
func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}
