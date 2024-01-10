// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"net/http"
	"time"
)

const (
	SignatureHeader      = "Signature"
	SignatureInputHeader = "Signature-Input"
	ContentDigestHeader  = "Content-Digest"
)

type Param string

const (
	ParamKeyID   Param = "keyid"
	ParamAlg     Param = "alg"
	ParamCreated Param = "created"
	ParamExpires Param = "expires"
	ParamNonce   Param = "nonce"
	ParamTag     Param = "tag"
)

var defaultParams = []Param{ParamKeyID, ParamAlg, ParamCreated}

type Algorithm string

const (
	AlgorithmRsaPkcs1v15Sha256 Algorithm = "rsa-v1_5-sha256"
	AlgorithmRsaPssSha512      Algorithm = "rsa-pss-sha512"
	AlgorithmEcdsaP256Sha256   Algorithm = "ecdsa-p256-sha256"
	AlgorithmEcdsaP384Sha384   Algorithm = "ecdsa-p384-sha384"
	AlgorithmEd25519           Algorithm = "ed25519"
	AlgorithmHmacSha256        Algorithm = "hmac-sha256"
)

type DigestAlgorithm string

const (
	DigestAlgorithmSha256 DigestAlgorithm = "sha-256"
	DigestAlgorithmSha512 DigestAlgorithm = "sha-512"
)

type SigningKey interface {
	Sign(data []byte) ([]byte, error)
	GetKeyID() string
	GetAlgorithm() Algorithm
}

// The signature parameters to include in signing
type SignatureParameters struct {
	// The created time for the signature. `nil` indicates not to populate the `created` time
	// default: time.Now()
	Created *time.Time

	// The time the signature should be deemed to have expired
	// default: time.Now() + 5 mins
	Expires *time.Time

	// A nonce for the request
	Nonce *string

	// The algorithm the signature is signed with (overrides the alg provided by the signing key)
	Alg *Algorithm

	// The key id the signature is signed with (overrides the keyid provided by the signing key)
	KeyID *string

	// A tag parameter for the signature
	Tag *string
}

type Signer struct {
	*signer
}

func NewSigner(opts ...signOption) *Signer {
	s := signer{}

	for _, o := range opts {
		o.configureSign(&s)
	}

	if len(s.config.Params) == 0 {
		s.config.Params = defaultParams[:]
	}

	return &Signer{&s}
}

func (s *Signer) Sign(m *Message) (http.Header, error) {
	return s.signer.Sign(m)
}

type VerifyingKey interface {
	Verify(data []byte, signature []byte) error
	GetKeyID() string
	GetAlgorithm() Algorithm
}

type VerifyingKeyResolver interface {
	Resolve(keyID string) (VerifyingKey, error)
}

type Verifier struct {
	*verifier
}

func NewVerifier(opts ...verifyOption) *Verifier {
	v := verifier{}

	v.config.Keys = make(map[string]VerifyingKey)

	for _, o := range opts {
		o.configureVerify(&v)
	}

	return &Verifier{&v}
}

func (v *Verifier) Verify(m *Message) error {
	err := v.verifier.Verify(m)
	if err != nil {
		return err
	}
	return nil
}

type Digestor struct {
	*digestor
}

func NewDigestor(opts ...digestOption) *Digestor {
	d := digestor{}

	for _, o := range opts {
		o.configureDigest(&d)
	}

	if len(d.config.Algorithms) == 0 {
		d.config.Algorithms = []DigestAlgorithm{DigestAlgorithmSha256}
	}

	return &Digestor{&d}
}
