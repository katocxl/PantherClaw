# Runbook — Key rotation

**Status:** broker keys, sealed credentials and the internal gateway CA are tested procedures (M6). The other rows are outlines for the milestones named.

| Key | Rotation | Procedure | In code today |
|---|---|---|---|
| Authority signing keys (receipts, permits, workload tokens, action tokens) | 90 days, ≥ 7-day overlap | new key published in JWKS as `next` → promote to `active` → old key `verify-only` for 7 days → retire; the ledger records each step | Key-store support only; no operator command yet |
| Envelope DEKs (per org/purpose) | yearly or on suspicion | create a new DEK version; new writes use it; a River job re-encrypts rows in batches; destroy the old version after verification | outline |
| KEK (key-encryption key files) | provider policy / on suspicion | rewrap all DEKs with the new KEK; verify decryption of samples; disable the old KEK | `pantherclaw-server keys gen-kek`; the gateway's `broker.kek_files` accepts old and new (§5) |
| Gateway broker keys | on suspicion, or when a gateway host is replaced | §5 | yes (M6) |
| Sealed connection credentials | at the provider's rotation, or on suspicion | §5.3 | yes (M6) |
| Internal gateway CA | on compromise, or planned with every gateway operator | §6: a new key, then every gateway re-enrolls | yes (M6): `pantherclaw-server keys rotate-gateway-ca`; without downtime in M13 |
| Offline roots (licence, package) | only on compromise | freeze promotions, publish revocation, re-sign with a new root, ship the root update in a signed release | procedure only |

Compromise of any key: treat it as an incident ([incident-response.md](incident-response.md)), rotate immediately and record G4.

## 5. Gateway broker keys (M6)

A gateway's broker key (X-Wing) opens the credentials sealed to it. It is generated on the gateway host and never leaves it. The private key is stored encrypted with a KEK file. Background: [g0/M6.md](../g0/M6.md) design decision 8; HR-060, HR-061, HR-182.

### 5.1 Generate and register a new key (gateway operator)

```bash
pantherclaw-gateway broker-key generate --out /etc/pantherclaw/broker-2.json --kek-file /etc/pantherclaw/kek
# broker key sha256:… written to …; give this fingerprint to whoever seals credentials
```

1. Point `broker.key_file` at the new file and restart the gateway.
2. At start the gateway registers the key over its mTLS identity, retrying until it succeeds; it serves nothing before.
3. The server records it as the next version and retires the previous one. A retired key can never be registered again (`BROKER_KEY_REUSED`).
4. Check with `pclaw gateway get <gateway-id>`: the new version is active, with the fingerprint printed by `generate`.

### 5.2 Re-seal every credential of the gateway's connections (credential owner)

Credentials sealed to the old key are still delivered to the gateway, but it can no longer open them. Calls through those connections fail with `enforcement_failed` / `credential_unavailable` until they are sealed again. So plan the restart and the re-sealing together:

```bash
pclaw credential list <connection-id>                              # versions, broker key, state
pclaw seal --connection <connection-id> --from-file secret.txt --fingerprint sha256:<new fingerprint>
```

`pclaw seal` asks for the active broker key of the connection's gateway, prints its fingerprint, and seals on your machine; the plaintext never leaves it. `--fingerprint` refuses to seal to any other key. If the key changes between the two steps, the upload is refused (`BROKER_KEY_CHANGED`): run `seal` again.

### 5.3 Rotate or revoke a credential

- **Rotate:** rotate at the provider, then `pclaw seal` the new value. The new version supersedes the old one.
- **Revoke:** `pclaw credential revoke <connection-id> <version>`. This raises the epoch, so outstanding permits fail. Replacing a credential is a weakening change and is notified to org admins.
- **KEK rotation for the broker key file:** a key file stays wrapped with the KEK it was generated with; nothing rewraps it. To retire a KEK:
  1. generate a new KEK (`pantherclaw-server keys gen-kek --out …`);
  2. generate a new broker key with it (§5.1);
  3. re-seal (§5.2);
  4. drop the old KEK from `broker.kek_files`.

## 6. Internal gateway CA

The internal CA (signing-key purpose `gateway_ca`) issues two things:
- the gateways' 24-hour client certificates;
- the gateway listener's server certificate.

The CA certificate is derived from the key, so its SHA-256 (`ca_sha256`) stays the same for the key's lifetime. Every gateway pins it at enrollment, and refuses a renewal that returns another CA.

Replacing the CA therefore means every gateway enrolls again. That is the M6 procedure (founder decision 2026-10-10). Rotation without downtime is planned for M13. Replace the CA when its key may be compromised, or on a planned schedule with every gateway's operator ready.

1. **Contain**, if the key may be compromised. Engage the kill switch when actions may have been authorized through a forged gateway ([kill-switch.md](kill-switch.md)), and follow [incident-response.md](incident-response.md).
2. **Replace the key** (server operator):
   ```bash
   pantherclaw-server keys rotate-gateway-ca --config server.json --confirm
   # replaced the gateway CA: new key …, pin sha256:… (was sha256:…); revoked 1 earlier key(s)
   ```
   One transaction creates the new key and revokes every earlier one, with no overlap. Without `--confirm` nothing changes.
3. **Restart every server instance**, so the listener presents a certificate from the new CA and trusts only it. From then on, every gateway is refused until it enrolls again: its pinned CA no longer matches.
4. **Re-enroll every gateway** ([gateway.md](gateway.md) §2–§3):
   - a gateway admin issues a new token with `pclaw gateway enroll-token`, which shows the new `ca_sha256`;
   - the operator sets `control.ca_sha256` to it and runs `pantherclaw-gateway enroll` again. A new identity replaces the old one in `identity_dir`.

   Broker keys and sealed credentials are unaffected: they belong to the gateway record, not to its certificate.
5. **Check:** `pclaw gateway get` shows a new certificate per gateway, and agent calls succeed again.
