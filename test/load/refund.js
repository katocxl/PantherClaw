// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// k6 load for the M1.5 walking skeleton against the SIMULATED payments target
// (Linux/nightly; `pantherclaw-sim load` is the local equivalent). Start the
// server with the dev gateway, `pantherclaw-sim payments` and the gateway as
// in BUILD_GUIDE §4, seed a budget large enough for the run, then:
//
//   k6 run -e WORKLOAD=<agent instance id> [-e GATEWAY=http://127.0.0.1:8090] \
//          [-e RATE=1000] [-e DURATION=60s] test/load/refund.js
//
// Thresholds are the SLOs: Authorize p99 <= 25 ms and gateway overhead p99 <=
// 35 ms at 1,000 requests per second. No remote modules are imported.
//
// Since M3 the gateway accepts only PAP/1-signed requests (an Ed25519 proof
// over every request), which k6 cannot produce; `pantherclaw-sim load` signs
// them and is the load driver from M3 on. This script records how the M1.5
// baseline in docs/perf/M1.5.md was measured.
import http from 'k6/http';
import crypto from 'k6/crypto';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const GATEWAY = __ENV.GATEWAY || 'http://127.0.0.1:8090';
const WORKLOAD = __ENV.WORKLOAD;
const RATE = Number(__ENV.RATE || 1000);

const authorize = new Trend('pc_authorize_ms', true);
const overhead = new Trend('pc_gateway_overhead_ms', true);

export const options = {
  discardResponseBodies: true,
  scenarios: {
    refunds: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: __ENV.DURATION || '60s',
      preAllocatedVUs: 200,
      maxVUs: 2000,
    },
  },
  thresholds: {
    pc_authorize_ms: ['p(50)>=0', 'p(95)>=0', 'p(99)<=25'],
    pc_gateway_overhead_ms: ['p(50)>=0', 'p(95)>=0', 'p(99)<=35'],
    http_req_failed: ['rate<0.001'],
  },
};

// uuid returns a random (version 4) canonical UUID.
function uuid() {
  const b = new Uint8Array(crypto.randomBytes(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// timing parses Server-Timing: "authz;dur=1.234, target;dur=0.5, ...".
function timing(header) {
  const out = {};
  for (const entry of String(header || '').split(',')) {
    const [name, dur] = entry.trim().split(';dur=');
    if (dur !== undefined) out[name] = Number(dur);
  }
  return out;
}

export function setup() {
  if (!WORKLOAD) throw new Error('set -e WORKLOAD=<agent instance id from the gateway config>');
  return { run: uuid() };
}

export default function (data) {
  const res = http.post(
    `${GATEWAY}/v1/refunds`,
    JSON.stringify({ charge: 'ch_k6load', amount: '1.00', currency: 'USD', reason: 'duplicate' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'PC-Dev-Workload': WORKLOAD,
        'PC-Run-Id': data.run,
        'PC-Action-Id': uuid(),
      },
    },
  );
  check(res, { accepted: (r) => r.status === 200 });
  if (res.status === 200) {
    const t = timing(res.headers['Server-Timing']);
    authorize.add(t.authz);
    overhead.add(t.total - t.target);
  }
}
