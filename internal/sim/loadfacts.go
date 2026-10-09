// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Since M4 every refund is decided by the pipeline: identical irreversible
// refunds are parked for the repeat window (HR-007), and a refund needs a
// fresh payments.charge.refundable fact about its charge. With --unique the
// driver refunds a distinct (charge, amount) pair per request, and with
// --facts-key-file it reports those charges as refundable first, as the
// development fact provider, and again every factsRefresh.

const (
	// amountsPerCharge distinct amounts (0.01 to 99.99 USD) are refunded
	// from one charge before the next charge is used.
	amountsPerCharge = 9999
	factsRefresh     = 2 * time.Minute
	factsPerCall     = 100
)

// runTag names one run's charges, so a later run never repeats a refund an
// earlier one completed (the repeat window outlives a run).
func runTag(now time.Time) string { return strconv.FormatInt(now.UnixNano(), 36) }

// uniqueRefund is the charge and amount of request i of the run tagged tag
// with --unique.
func uniqueRefund(tag string, i int) (charge, amount string) {
	cents := i%amountsPerCharge + 1
	return fmt.Sprintf("ch_%sn%d", tag, i/amountsPerCharge), fmt.Sprintf("%d.%02d", cents/100, cents%100)
}

// chargesFor lists the charges total requests use.
func chargesFor(tag string, total int, unique bool) []string {
	if !unique {
		return []string{"ch_load1"}
	}
	n := (total + amountsPerCharge - 1) / amountsPerCharge
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("ch_%sn%d", tag, i))
	}
	return out
}

type apiKey string

func (k apiKey) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(k))
	return http.DefaultTransport.RoundTrip(r)
}

// factReporter reports charges as refundable through FactService.
type factReporter struct {
	client  pantherclawv1connect.FactServiceClient
	charges []string
}

func newFactReporter(server, keyFile string, charges []string) (*factReporter, error) {
	b, err := os.ReadFile(keyFile) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return nil, fmt.Errorf("--facts-key-file: %w", err)
	}
	if server == "" {
		return nil, fmt.Errorf("--facts-key-file needs the server: the workload key file names none")
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: apiKey(strings.TrimSpace(string(b)))}
	return &factReporter{
		client:  pantherclawv1connect.NewFactServiceClient(connect.NewClient(connecthttp.NewTransport(hc, strings.TrimSuffix(server, "/")))),
		charges: charges,
	}, nil
}

// report sends one observation per charge, now; every one must be
// accepted.
func (f *factReporter) report(ctx context.Context) error {
	for rest := f.charges; len(rest) > 0; {
		n := min(len(rest), factsPerCall)
		req := &pantherclawv1.PutFactsRequest{}
		for _, c := range rest[:n] {
			req.Observations = append(req.Observations, &pantherclawv1.FactObservation{
				Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectId: c, Value: []byte(`{"bool":true}`),
				ObserveTime: timestamppb.Now(),
			})
		}
		res, err := f.client.PutFacts(ctx, req)
		if err != nil {
			return fmt.Errorf("report facts: %w", err)
		}
		for _, r := range res.GetResults() {
			if !r.GetAccepted() {
				return fmt.Errorf("report facts: %s refused: %s %s", rest[r.GetIndex()], r.GetCode(), r.GetDetail())
			}
		}
		rest = rest[n:]
	}
	return nil
}

// refresh reports the facts again every factsRefresh until ctx ends; a
// failure is printed, and the refunds then fail closed (FACT_STALE).
func (f *factReporter) refresh(ctx context.Context, warn func(error)) {
	t := time.NewTicker(factsRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := f.report(ctx); err != nil && ctx.Err() == nil {
				warn(err)
			}
		}
	}
}
