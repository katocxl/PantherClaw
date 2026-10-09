// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

func TestHR056_DeliveryJobsCarryIDsOnly(t *testing.T) {
	if err := jobs.CheckArgs(reflect.TypeFor[napp.DeliverArgs]()); err != nil {
		t.Fatal(err)
	}
}

// TestHR039_OnlyNotificationsReadDeliveryState is the part-1 half of
// HR-039: delivery state (delivered, failed, acknowledged) can never reach
// an authorization decision, because no query outside the notifications
// module touches the deliveries table.
func TestHR039_OnlyNotificationsReadDeliveryState(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "queries", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no query files found: %v", err)
	}
	uses := regexp.MustCompile(`(?i)\bpc\.deliveries\b`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Base(f)
		if strings.HasPrefix(base, "notifications") {
			continue
		}
		if uses.Match(b) {
			t.Errorf("%s uses pc.deliveries: delivery state belongs to internal/notifications only (HR-039)", base)
		}
	}
}
