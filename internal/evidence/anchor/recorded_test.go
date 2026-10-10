// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Recorded Sigstore responses (testdata/sigstore-conformance/README.md):
// real Rekor v2 entries and RFC 3161 tokens, read offline.

var recordedCases = []string{"rekor2-happy-path", "rekor2-timestamp-without-embedded-cert"}

type recordedBundle struct {
	VerificationMaterial struct {
		Certificate struct {
			RawBytes []byte `json:"rawBytes"`
		} `json:"certificate"`
		TlogEntries               []jsontext.Value `json:"tlogEntries"`
		TimestampVerificationData struct {
			RFC3161Timestamps []struct {
				SignedTimestamp []byte `json:"signedTimestamp"`
			} `json:"rfc3161Timestamps"`
		} `json:"timestampVerificationData"`
	} `json:"verificationMaterial"`
	MessageSignature struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    []byte `json:"digest"`
		} `json:"messageDigest"`
		Signature []byte `json:"signature"`
	} `json:"messageSignature"`
}

type recordedTrustedRoot struct {
	Tlogs []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey struct {
			RawBytes   []byte `json:"rawBytes"`
			KeyDetails string `json:"keyDetails"`
		} `json:"publicKey"`
	} `json:"tlogs"`
	TimestampAuthorities []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
	} `json:"timestampAuthorities"`
}

func readJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sigstore-conformance", path))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func recordedBundleFor(t testing.TB, name string) recordedBundle {
	t.Helper()
	var b recordedBundle
	readJSON(t, filepath.Join(name, "bundle.sigstore.json"), &b)
	if len(b.VerificationMaterial.TlogEntries) != 1 || len(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps) != 1 {
		t.Fatalf("%s: unexpected bundle shape", name)
	}
	return b
}

// recordedLog returns the Rekor v2 log of the recorded trusted root: its
// origin is the scheme-less base URL.
func recordedLog(t testing.TB) Log {
	t.Helper()
	var r recordedTrustedRoot
	readJSON(t, "trusted_root.json", &r)
	for _, l := range r.Tlogs {
		if origin, ok := strings.CutPrefix(l.BaseURL, "https://"); ok && strings.HasPrefix(origin, "log2025") {
			log, err := NewLog(origin, l.PublicKey.RawBytes)
			if err != nil {
				t.Fatal(err)
			}
			return log
		}
	}
	t.Fatal("no Rekor v2 log in the recorded trusted root")
	return Log{}
}

func recordedTSAChain(t testing.TB) []*x509.Certificate {
	t.Helper()
	var r recordedTrustedRoot
	readJSON(t, "trusted_root.json", &r)
	var chain []*x509.Certificate
	for _, c := range r.TimestampAuthorities[0].CertChain.Certificates {
		cert, err := x509.ParseCertificate(c.RawBytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return chain
}
