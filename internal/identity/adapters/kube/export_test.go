// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kube

// NewClientWithClock lets tests control when the reviewer token is read
// again.
var NewClientWithClock = newClient

// TokenRefresh is how long a reviewer token is used before its file is read
// again.
const TokenRefresh = tokenRefresh
