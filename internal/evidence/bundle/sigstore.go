// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor"
)

// MaxSigstoreRootBytes caps a trusted_root.json.
const MaxSigstoreRootBytes = 1 << 20

// ErrInvalidSigstoreRoot reports a trusted_root.json that cannot be used.
var ErrInvalidSigstoreRoot = errors.New("bundle: invalid Sigstore trusted root")

// SigstoreRoot is what `pclaw verify` uses from a Sigstore trusted root
// (protobuf-specs TrustedRoot, trusted_root.json): the transparency logs'
// origins and keys, and the timestamp authorities' certificate chains with
// their validity. The user supplies the file; PantherClaw runs no TUF
// client (G0 M7 design decision 12).
type SigstoreRoot struct {
	Logs []anchor.Log
	TSAs []*anchor.TSAVerifier
}

type timeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end,omitzero"`
}

type trustedRoot struct {
	MediaType string `json:"mediaType"`
	Tlogs     []struct {
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
		ValidFor timeRange `json:"validFor"`
	} `json:"timestampAuthorities"`
}

// ParseSigstoreRoot reads the logs with an Ed25519 or ECDSA P-256 key
// (others are skipped) and every timestamp authority. A log's origin is
// its base URL without the scheme, as Rekor v2 checkpoints carry it.
func ParseSigstoreRoot(b []byte) (*SigstoreRoot, error) {
	if len(b) > MaxSigstoreRootBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidSigstoreRoot, MaxSigstoreRootBytes)
	}
	var tr trustedRoot
	if err := json.Unmarshal(b, &tr); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSigstoreRoot, err)
	}
	if !strings.HasPrefix(tr.MediaType, "application/vnd.dev.sigstore.trustedroot") {
		return nil, fmt.Errorf("%w: media type %q", ErrInvalidSigstoreRoot, truncate(tr.MediaType))
	}
	root := &SigstoreRoot{}
	for _, l := range tr.Tlogs {
		switch l.PublicKey.KeyDetails {
		case "PKIX_ED25519", "PKIX_ECDSA_P256_SHA_256":
		default:
			continue
		}
		origin := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(l.BaseURL, "https://"), "http://"), "/")
		log, err := anchor.NewLog(origin, l.PublicKey.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: log %s: %w", ErrInvalidSigstoreRoot, truncate(origin), err)
		}
		root.Logs = append(root.Logs, log)
	}
	for _, a := range tr.TimestampAuthorities {
		var chain []*x509.Certificate
		for _, c := range a.CertChain.Certificates {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: timestamp authority certificate: %w", ErrInvalidSigstoreRoot, err)
			}
			chain = append(chain, cert)
		}
		v, err := anchor.NewTSAVerifier(chain)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSigstoreRoot, err)
		}
		root.TSAs = append(root.TSAs, v.WithValidity(a.ValidFor.Start, a.ValidFor.End))
	}
	if len(root.Logs) == 0 && len(root.TSAs) == 0 {
		return nil, fmt.Errorf("%w: no usable log or timestamp authority", ErrInvalidSigstoreRoot)
	}
	return root, nil
}
