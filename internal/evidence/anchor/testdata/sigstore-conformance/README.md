# Recorded Sigstore responses (known-answer tests)

These files are copied unchanged from the Sigstore conformance suite,
<https://github.com/sigstore/sigstore-conformance>, directory
`test/assets/bundle-verify/`, licensed under the Apache License 2.0
(Copyright The Sigstore Authors):

- `rekor2-happy-path/bundle.sigstore.json`: a bundle whose entry was logged in
  Sigstore's Rekor v2 staging log (`log2025-alpha1.rekor.sigstage.dev`) as a
  hashedrekord v0.0.2 entry, with the log's checkpoint, the inclusion proof and
  an RFC 3161 timestamp from `timestamp.sigstage.dev` with an embedded signer
  certificate.
- `rekor2-timestamp-without-embedded-cert/bundle.sigstore.json`: the same kind
  of bundle, with a timestamp token that does not embed its certificate.
- `trusted_root.json`: the staging trusted root that both bundles use (the Rekor
  v2 log key and the timestamp authority's certificate chain).

They let the anchor client's verifiers be tested against real Rekor v2 and RFC
3161 responses without any network call (G0 M7 design decision 12). The tests
never contact a Sigstore service.
