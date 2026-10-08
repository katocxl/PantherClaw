# Runbook — Security incident in PantherClaw itself

**Status:** stub (completed in M10).

1. **Detect & declare:** source (report, alert, scanner), time, affected component/version; open a private security advisory; record G4.
2. **Contain:** engage kill switch for affected orgs if enforcement integrity is in doubt; revoke/rotate affected keys; disable compromised releases (mark release as compromised, publish notice); freeze package/licence signing if roots are suspected.
3. **Preserve evidence:** snapshot DB, ledger checkpoints, logs, CI run logs; do not modify the ledger.
4. **Eradicate & recover:** fix with reproducing test → two AI reviews → G1 → patched release (G2/G3) → restoration per kill-switch runbook.
5. **Notify:** affected customers with scope, timeline, residual risk; publish advisory/CVE when fixed.
6. **Learn:** update THREAT_MODEL, HARDENING_RULES (new HR + test), FINDINGS (closed row).
