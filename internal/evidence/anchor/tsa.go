// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"time"
)

// RFC 3161 time-stamp protocol, with the token verified as CMS SignedData
// (RFC 5652) on encoding/asn1 and crypto/x509: one signer, signed
// attributes (content type and message digest), ECDSA or RSA PKCS #1 v1.5
// with SHA-256/384/512, a signer certificate with the critical
// timeStamping extended key usage only, and a chain to the configured
// authority's root at the time of the timestamp. Following Sigstore, the
// timestamp is over the anchor statement's signature: the message imprint
// is SHA-256(signature).

const (
	// MaxTokenBytes caps a timestamp token or response.
	MaxTokenBytes = 64 << 10
	// nonceBytes is the size of a request nonce.
	nonceBytes = 16
)

// ErrInvalidTimestamp reports a timestamp response or token that is
// malformed or does not verify.
var ErrInvalidTimestamp = errors.New("anchor: invalid timestamp")

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidExtKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 37}
)

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// TimestampRequest is an RFC 3161 request over a statement's signature.
type TimestampRequest struct {
	Imprint [sha256.Size]byte // SHA-256 of the signature
	Nonce   *big.Int          // fresh, positive
}

// NewTimestampRequest returns a request for the timestamp of signature,
// with a fresh 128-bit nonce.
func NewTimestampRequest(signature []byte) (TimestampRequest, error) {
	if len(signature) == 0 {
		return TimestampRequest{}, errors.New("anchor: nothing to timestamp")
	}
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return TimestampRequest{}, fmt.Errorf("anchor: nonce: %w", err)
	}
	b[0] |= 0x40 // a full-size positive nonce
	b[0] &= 0x7f
	return TimestampRequest{Imprint: sha256.Sum256(signature), Nonce: new(big.Int).SetBytes(b)}, nil
}

// Marshal returns the DER TimeStampReq: version 1, a SHA-256 message
// imprint, the nonce and certReq (the signer's certificate is requested).
func (r TimestampRequest) Marshal() ([]byte, error) {
	if r.Nonce == nil || r.Nonce.Sign() <= 0 {
		return nil, errors.New("anchor: the request needs a positive nonce")
	}
	return asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: r.Imprint[:],
		},
		Nonce:   r.Nonce,
		CertReq: true,
	})
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// ParseResponse decodes a TimeStampResp and returns its token (a DER
// ContentInfo). Only the statuses granted (0) and grantedWithMods (1) carry
// a token.
func ParseResponse(der []byte) ([]byte, error) {
	if len(der) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidTimestamp, MaxTokenBytes)
	}
	var resp timeStampResp
	if err := unmarshalAll(der, &resp); err != nil {
		return nil, fmt.Errorf("%w: response: %w", ErrInvalidTimestamp, err)
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("%w: the authority refused (status %d)", ErrInvalidTimestamp, resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("%w: no token", ErrInvalidTimestamp)
	}
	return resp.TimeStampToken.FullBytes, nil
}

// unmarshalAll decodes exactly one DER value.
func unmarshalAll(der []byte, v any) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

// The [0] EXPLICIT members below are read as raw values and unwrapped by
// explicit (encoding/asn1 keeps the wrapper of an explicitly tagged
// RawValue).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional"`
}

// explicit returns the single element inside a [0] EXPLICIT wrapper.
func explicit(w asn1.RawValue) (asn1.RawValue, error) {
	var inner asn1.RawValue
	if w.Class != asn1.ClassContextSpecific || w.Tag != 0 || !w.IsCompound {
		return inner, errors.New("missing [0] wrapper")
	}
	if err := unmarshalAll(w.Bytes, &inner); err != nil {
		return inner, err
	}
	return inner, nil
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,explicit,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// Timestamp is a verified timestamp.
type Timestamp struct {
	Time   time.Time // genTime
	Policy asn1.ObjectIdentifier
	Serial *big.Int
	Nonce  *big.Int // nil when the token has none
	Signer *x509.Certificate
}

// TSAVerifier verifies tokens of one timestamp authority.
type TSAVerifier struct {
	certs         []*x509.Certificate
	roots         *x509.CertPool
	intermediates *x509.CertPool
	validFrom     time.Time // optional window of the authority (trusted root)
	validUntil    time.Time
}

// NewTSAVerifier returns a verifier for the authority whose certificate
// chain is chain, the signing certificate first and the trust anchor (the
// authority's root) last, as tsa.cert_chain_file and Sigstore's
// trusted_root.json list it.
func NewTSAVerifier(chain []*x509.Certificate) (*TSAVerifier, error) {
	if len(chain) == 0 {
		return nil, errors.New("anchor: empty timestamp authority chain")
	}
	v := &TSAVerifier{certs: slices.Clone(chain), roots: x509.NewCertPool(), intermediates: x509.NewCertPool()}
	v.roots.AddCert(chain[len(chain)-1])
	for _, c := range chain[:len(chain)-1] {
		v.intermediates.AddCert(c)
	}
	return v, nil
}

// WithValidity limits the authority to timestamps in [from, until]; a zero
// bound is open.
func (v *TSAVerifier) WithValidity(from, until time.Time) *TSAVerifier {
	c := *v
	c.validFrom, c.validUntil = from, until
	return &c
}

// ParseCertificateChain decodes a PEM certificate chain (CERTIFICATE blocks
// only), in file order.
func ParseCertificateChain(pemData []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, pemData = pem.Decode(pemData)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("anchor: unexpected PEM block %q in a certificate chain", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("anchor: certificate chain: %w", err)
		}
		out = append(out, c)
	}
	if len(bytes.TrimSpace(pemData)) != 0 || len(out) == 0 {
		return nil, errors.New("anchor: certificate chain must be PEM certificates only")
	}
	return out, nil
}

// Verify checks a timestamp offline: a DER TimeStampResp (what the client
// keeps, and what Sigstore bundles carry as signedTimestamp) or a bare
// TimeStampToken. It checks the CMS signature, the signer's certificate and
// chain at the timestamp's time, and the message imprint SHA-256(signature).
func (v *TSAVerifier) Verify(timestamp, signature []byte) (*Timestamp, error) {
	token, err := tokenOf(timestamp)
	if err != nil {
		return nil, err
	}
	ts, err := v.verify(token, sha256.Sum256(signature))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTimestamp, err)
	}
	return ts, nil
}

// tokenOf returns the token of a TimeStampResp, or a bare token as is: a
// response starts with its status (a SEQUENCE), a token with an OID.
func tokenOf(der []byte) ([]byte, error) {
	var outer, first asn1.RawValue
	if err := unmarshalAll(der, &outer); err != nil || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("%w: not a timestamp response or token", ErrInvalidTimestamp)
	}
	if _, err := asn1.Unmarshal(outer.Bytes, &first); err != nil {
		return nil, fmt.Errorf("%w: not a timestamp response or token", ErrInvalidTimestamp)
	}
	if first.Class == asn1.ClassUniversal && first.Tag == asn1.TagSequence {
		return ParseResponse(der)
	}
	return der, nil
}

// VerifyResponse decodes the authority's response to req and verifies its
// token, including the nonce.
func (v *TSAVerifier) VerifyResponse(resp []byte, req TimestampRequest) (*Timestamp, error) {
	token, err := ParseResponse(resp)
	if err != nil {
		return nil, err
	}
	ts, err := v.verify(token, req.Imprint)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTimestamp, err)
	}
	if ts.Nonce == nil || req.Nonce == nil || ts.Nonce.Cmp(req.Nonce) != 0 {
		return nil, fmt.Errorf("%w: the nonce does not match the request", ErrInvalidTimestamp)
	}
	return ts, nil
}

func (v *TSAVerifier) verify(token []byte, imprint [sha256.Size]byte) (*Timestamp, error) {
	if len(token) > MaxTokenBytes {
		return nil, fmt.Errorf("token larger than %d bytes", MaxTokenBytes)
	}
	var ci contentInfo
	if err := unmarshalAll(token, &ci); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("token is not CMS SignedData")
	}
	inner, err := explicit(ci.Content)
	if err != nil {
		return nil, fmt.Errorf("signed data: %w", err)
	}
	var sd signedData
	if err := unmarshalAll(inner.FullBytes, &sd); err != nil {
		return nil, fmt.Errorf("signed data: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, errors.New("the signed content is not a TSTInfo")
	}
	ec, err := explicit(sd.EncapContentInfo.EContent)
	if err != nil || ec.Class != asn1.ClassUniversal || ec.Tag != asn1.TagOctetString || ec.IsCompound || len(ec.Bytes) == 0 {
		return nil, errors.New("the TSTInfo must be one OCTET STRING")
	}
	content := ec.Bytes
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%d signers, want 1", len(sd.SignerInfos))
	}
	var si signerInfo
	if err := unmarshalAll(sd.SignerInfos[0].FullBytes, &si); err != nil {
		return nil, fmt.Errorf("signer info: %w", err)
	}
	embedded, err := embeddedCerts(sd.Certificates)
	if err != nil {
		return nil, err
	}
	signer, err := findSigner(si.SID, embedded, v.certs)
	if err != nil {
		return nil, err
	}
	hash, err := digestHash(si.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	signed, err := checkSignedAttrs(si.SignedAttrs, hash, content)
	if err != nil {
		return nil, err
	}
	alg, err := signatureAlgorithm(si.SignatureAlgorithm, hash)
	if err != nil {
		return nil, err
	}
	if err := signer.CheckSignature(alg, signed, si.Signature); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	var info tstInfo
	if err := unmarshalAll(content, &info); err != nil {
		return nil, fmt.Errorf("TSTInfo: %w", err)
	}
	if info.Version != 1 {
		return nil, fmt.Errorf("TSTInfo version %d", info.Version)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) || !nullOrAbsent(info.MessageImprint.HashAlgorithm.Parameters) ||
		!bytes.Equal(info.MessageImprint.HashedMessage, imprint[:]) {
		return nil, errors.New("the message imprint is not SHA-256 of the signature")
	}
	if err := v.checkSigner(signer, embedded, info.GenTime); err != nil {
		return nil, err
	}
	return &Timestamp{Time: info.GenTime, Policy: info.Policy, Serial: info.SerialNumber, Nonce: info.Nonce, Signer: signer}, nil
}

func embeddedCerts(raw asn1.RawValue) ([]*x509.Certificate, error) {
	if len(raw.FullBytes) == 0 {
		return nil, nil
	}
	if !raw.IsCompound {
		return nil, errors.New("malformed certificate set")
	}
	certs, err := x509.ParseCertificates(raw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("embedded certificates: %w", err)
	}
	return certs, nil
}

// findSigner returns the certificate that the signer identifier names,
// among the embedded and the configured certificates.
func findSigner(sid asn1.RawValue, lists ...[]*x509.Certificate) (*x509.Certificate, error) {
	var match func(*x509.Certificate) bool
	switch {
	case sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence:
		var ias issuerAndSerial
		if err := unmarshalAll(sid.FullBytes, &ias); err != nil || ias.Serial == nil {
			return nil, errors.New("malformed signer identifier")
		}
		match = func(c *x509.Certificate) bool {
			return bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0
		}
	case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 && !sid.IsCompound:
		match = func(c *x509.Certificate) bool { return len(sid.Bytes) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) }
	default:
		return nil, errors.New("malformed signer identifier")
	}
	for _, l := range lists {
		for _, c := range l {
			if match(c) {
				return c, nil
			}
		}
	}
	return nil, errors.New("the signer's certificate is neither in the token nor in the authority's chain")
}

func digestHash(alg pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	if !nullOrAbsent(alg.Parameters) {
		return 0, errors.New("unexpected digest parameters")
	}
	switch {
	case alg.Algorithm.Equal(oidSHA256):
		return crypto.SHA256, nil
	case alg.Algorithm.Equal(oidSHA384):
		return crypto.SHA384, nil
	case alg.Algorithm.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("digest algorithm %v not allowed", alg.Algorithm)
}

func nullOrAbsent(p asn1.RawValue) bool {
	return len(p.FullBytes) == 0 || bytes.Equal(p.FullBytes, asn1.NullBytes)
}

// rsaWithDigest is RSA PKCS #1 v1.5 for each allowed digest.
var rsaWithDigest = map[crypto.Hash]x509.SignatureAlgorithm{
	crypto.SHA256: x509.SHA256WithRSA, crypto.SHA384: x509.SHA384WithRSA, crypto.SHA512: x509.SHA512WithRSA,
}

// signatureAlgorithm maps the signer's algorithm to x509's: ECDSA with
// SHA-256/384/512, or RSA PKCS #1 v1.5 (given as rsaEncryption with the
// digest algorithm, or as shaNNNWithRSAEncryption).
func signatureAlgorithm(alg pkix.AlgorithmIdentifier, digest crypto.Hash) (x509.SignatureAlgorithm, error) {
	a := alg.Algorithm
	switch {
	case a.Equal(oidECDSAWithSHA256) && len(alg.Parameters.FullBytes) == 0:
		return x509.ECDSAWithSHA256, nil
	case a.Equal(oidECDSAWithSHA384) && len(alg.Parameters.FullBytes) == 0:
		return x509.ECDSAWithSHA384, nil
	case a.Equal(oidECDSAWithSHA512) && len(alg.Parameters.FullBytes) == 0:
		return x509.ECDSAWithSHA512, nil
	case !nullOrAbsent(alg.Parameters):
		return 0, errors.New("unexpected signature parameters")
	case a.Equal(oidSHA256WithRSA):
		return x509.SHA256WithRSA, nil
	case a.Equal(oidSHA384WithRSA):
		return x509.SHA384WithRSA, nil
	case a.Equal(oidSHA512WithRSA):
		return x509.SHA512WithRSA, nil
	case a.Equal(oidRSAEncryption):
		if alg, ok := rsaWithDigest[digest]; ok {
			return alg, nil
		}
	}
	return 0, fmt.Errorf("signature algorithm %v not allowed", a)
}

// checkSignedAttrs checks the signed attributes (exactly one content type,
// the TSTInfo, and one message digest, equal to the content's digest) and
// returns the bytes the signature covers: the attributes encoded as a SET.
func checkSignedAttrs(raw asn1.RawValue, hash crypto.Hash, content []byte) ([]byte, error) {
	if len(raw.FullBytes) == 0 || raw.FullBytes[0] != 0xa0 {
		return nil, errors.New("the token has no signed attributes")
	}
	signed := bytes.Clone(raw.FullBytes)
	signed[0] = 0x31 // SET OF, as signed (RFC 5652 §5.4)
	var attrs []attribute
	rest, err := asn1.UnmarshalWithParams(signed, &attrs, "set")
	if err != nil || len(rest) != 0 {
		return nil, errors.New("malformed signed attributes")
	}
	seen := map[string]bool{}
	var contentType, digest []byte
	for _, a := range attrs {
		k := a.Type.String()
		if seen[k] {
			return nil, fmt.Errorf("signed attribute %s repeated", k)
		}
		seen[k] = true
		switch {
		case a.Type.Equal(oidContentType):
			if len(a.Values) != 1 {
				return nil, errors.New("content type must have one value")
			}
			contentType = a.Values[0].FullBytes
		case a.Type.Equal(oidMessageDigest):
			if len(a.Values) != 1 {
				return nil, errors.New("message digest must have one value")
			}
			var d []byte
			if err := unmarshalAll(a.Values[0].FullBytes, &d); err != nil {
				return nil, errors.New("malformed message digest")
			}
			digest = d
		}
	}
	var ct asn1.ObjectIdentifier
	if contentType == nil || unmarshalAll(contentType, &ct) != nil || !ct.Equal(oidTSTInfo) {
		return nil, errors.New("the content-type attribute is not TSTInfo")
	}
	h := hash.New()
	h.Write(content)
	if digest == nil || !bytes.Equal(digest, h.Sum(nil)) {
		return nil, errors.New("the message-digest attribute does not match the TSTInfo")
	}
	return signed, nil
}

// checkSigner checks the signing certificate: only the timeStamping
// extended key usage, marked critical (RFC 3161 §2.3), and a chain to the
// authority's root valid at the timestamp's time, which must fall within
// the authority's validity.
func (v *TSAVerifier) checkSigner(signer *x509.Certificate, embedded []*x509.Certificate, at time.Time) error {
	critical := false
	for _, e := range signer.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			critical = e.Critical
		}
	}
	if !critical || len(signer.UnknownExtKeyUsage) != 0 ||
		!slices.Equal(signer.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}) {
		return errors.New("the signer is not a timestamping certificate (critical timeStamping EKU only)")
	}
	if (!v.validFrom.IsZero() && at.Before(v.validFrom)) || (!v.validUntil.IsZero() && at.After(v.validUntil)) {
		return errors.New("the timestamp is outside the authority's validity")
	}
	inter := v.intermediates.Clone()
	for _, c := range embedded {
		inter.AddCert(c)
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots: v.roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return fmt.Errorf("the signer's chain: %w", err)
	}
	return nil
}

// TSAClient requests RFC 3161 timestamps.
type TSAClient struct {
	URL      string // the authority's https URL
	HTTP     Doer
	Verifier *TSAVerifier
}

// Timestamp requests a timestamp over signature and returns the verified
// DER TimeStampResp, which is kept with the anchor (the form Sigstore
// bundles keep; Verify reads it offline). The anchor counts only if this
// succeeds (HR-195).
func (c *TSAClient) Timestamp(ctx context.Context, signature []byte) ([]byte, *Timestamp, error) {
	if c.Verifier == nil {
		return nil, nil, errors.New("anchor: no timestamp authority chain configured")
	}
	treq, err := NewTimestampRequest(signature)
	if err != nil {
		return nil, nil, err
	}
	body, err := treq.Marshal()
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := endpointURL(c.URL, "")
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("anchor: timestamp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	resp, err := send(c.HTTP, req, MaxTokenBytes, http.StatusOK)
	if err != nil {
		return nil, nil, fmt.Errorf("anchor: timestamp authority: %w", err)
	}
	ts, err := c.Verifier.VerifyResponse(resp, treq)
	if err != nil {
		return nil, nil, err
	}
	return resp, ts, nil
}
