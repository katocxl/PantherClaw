# Runbook — Org kill switch (emergency stop)

**Milestone:** M6 · **Owner:** the org's emergency responders · **Status:** tested procedure (M6 tests: engage, two-person restore, gateway refusal within a second)

The kill switch stops every agent action of one org at once, everywhere PantherClaw decides or dispatches. Background: [g0/M6.md](../g0/M6.md) design decisions 4 and 5; HR-113, HR-002, HR-010.

## Who and where

- Engaging and restoring happen **only on the emergency-stop page**, `<public URL>/containment?org=<org>`, in a signed-in browser. No CLI or API engages or restores. `ContainmentService` only reads.
- They need the human-only permission `containment.killswitch`, held by the `emergency_responder` role. Org admins and security admins do not hold it unless they also have that role.
- Each engage, proposal and confirmation needs a WebAuthn step-up on that browser session less than 5 minutes old, with an active key of yours.
- Anyone with `containment.read` can check the state:
  ```bash
  pclaw killswitch status    # engaged, epoch, who, when, why, any pending restore; prints the page link on stderr
  ```

## Engage

1. Open the emergency-stop page and step up with your security key or passkey.
2. Give a reason (1–500 characters; stored and shown as untrusted text) and engage.

One transaction:
- sets the kill switch and raises the containment epoch;
- records who, when and why;
- writes `security.kill_switch_engaged` to the ledger, with the epoch, the key used and, per connection, what else was done ("credential revocation at the provider: not supported" and "automations paused: none exist" in M6);
- notifies org admins (Critical).

Effects:
- every permit issued before fails `BeginDispatch`;
- `Authorize` denies;
- gateways refuse every action locally as soon as their containment stream carries the change (the server polls every 250 ms and sends a heartbeat every 500 ms). Agents get `enforcement_failed` / `kill_switch`;
- monitor-mode routes stop too.

A gateway that hears nothing for 2 seconds refuses everything anyway (`containment_stale`).

Honest limits:
- requests already sent to a target complete;
- credentials at providers are not revoked;
- routes PantherClaw does not mediate are unaffected;
- nothing is undone: transactions keep their recorded outcomes, and grants, runs and credentials stay as they were. So restoring brings back exactly what was there.

## Restore (two people)

1. A responder proposes a restore on the page, with step-up.
2. A **different** responder confirms within 30 minutes, with step-up, using a **different** security key or passkey. The same person, or the same key, is refused.
3. The confirmation clears the kill switch and raises the epoch in one transaction.

Either person can cancel a pending proposal (no step-up). Every step is audited (`…_restore_proposed`, `…_restored`, `…_restore_canceled`) and notified.

Before confirming, check that the cause is handled:
- the agents and instances involved are suspended or re-verified;
- the connections are healthy (`pclaw connection list`), and any you distrust are quarantined;
- grants and waiting approvals that should not survive are revoked or declined.

Nothing refused while the switch was engaged is replayed. Agents run their actions again, and each is decided anew. For an incident in PantherClaw itself, see [incident-response.md](incident-response.md).

## Errors on the page

| Code | Meaning |
|---|---|
| `step_up_required` | Step up again: the last one is older than 5 minutes, or the key is not active. |
| `reason_required` | Give a reason of 1–500 characters. |
| `already_engaged`, `not_engaged` | The switch is already in that state. |
| `restore_pending` | A restore is already proposed: confirm or cancel it. |
| `restore_gone` | The proposal expired (30 minutes) or was canceled: propose again. |
| `same_person`, `same_key` | The confirmation must come from another person, with another key. |
