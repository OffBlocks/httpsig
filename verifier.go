// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"slices"
	"time"

	"github.com/dunglas/httpsfv"
)

type VerifyConfig struct {
	// The keys to use for signing
	Keys map[string]VerifyingKey

	// Resolver for verifying keys
	KeyResolver VerifyingKeyResolver

	// A date that the signature can't have been marked as `created` after
	// Default: time.Now() + tolerance
	NotAfter *time.Time

	// The maximum age of the signature - this effectively overrides the `expires` value for the
	// signature (unless the expires age is less than the maxAge specified) if provided
	MaxAge *time.Duration

	// A clock tolerance when verifying created/expires times
	// Default: 0
	Tolerance *time.Duration

	// Any parameters that *must* be in the signature (eg: require a created time)
	// Default: []
	RequiredParams []string

	// Any fields that *must* be in the signature (eg: Authorization, Digest, etc)
	// Default: []
	RequiredFields []string

	// Verify every signature in the request. By default, only 1 signature will need to be valid
	// for the verification to pass.
	// Default: false
	All bool
}

type clock interface {
	Now() time.Time
}

type verifier struct {
	config VerifyConfig

	// for testing
	clock clock
}

// XXX: note about fail fast.
func (v *verifier) Verify(msg *Message) error {
	signatureHeader, ok := msg.Header[SignatureHeader]
	if !ok {
		return errNotSigned
	}
	inputHeader, ok := msg.Header[SignatureInputHeader]
	if !ok {
		return errNotSigned
	}

	signatureHeaderDict, err := httpsfv.UnmarshalDictionary(signatureHeader)
	if err != nil {
		return err
	}
	inputHeaderDict, err := httpsfv.UnmarshalDictionary(inputHeader)
	if err != nil {
		return err
	}

	// no signatures means an indeterminate result
	if len(signatureHeaderDict.Names()) == 0 && len(inputHeaderDict.Names()) == 0 {
		return errNotSigned
	}

	// a missing header means we can't verify the signatures
	if len(signatureHeaderDict.Names()) != len(inputHeaderDict.Names()) {
		return errNotSigned
	}

	var now time.Time
	if v.clock != nil {
		now = v.clock.Now()
	} else {
		now = time.Now()
	}
	var tolerance time.Duration
	if v.config.Tolerance != nil {
		tolerance = *v.config.Tolerance
	} else {
		tolerance = 0
	}
	var notAfter time.Time
	if v.config.NotAfter != nil {
		notAfter = *v.config.NotAfter
	} else {
		notAfter = now.Add(tolerance)
	}
	var maxAge *time.Duration
	if v.config.MaxAge != nil {
		maxAge = v.config.MaxAge
	}

	for _, name := range signatureHeaderDict.Names() {
		sigItem, ok := signatureHeaderDict.Get(name)
		if !ok {
			return errMalformedSignature
		}
		sigInputItem, ok := inputHeaderDict.Get(name)
		if !ok {
			return errMalformedSignature
		}
		signature, ok := sigItem.(httpsfv.Item)
		if !ok {
			return errMalformedSignature
		}
		signatureBytes, ok := signature.Value.([]byte)
		if !ok {
			return errMalformedSignature
		}
		signatureInput, ok := sigInputItem.(httpsfv.InnerList)
		if !ok {
			return errMalformedSignature
		}

		signatureParams, err := parseParams(signatureInput.Params)
		if err != nil {
			return err
		}

		var fields []string
		for _, item := range signatureInput.Items {
			marshalled, err := httpsfv.Marshal(item)
			if err != nil {
				return err
			}
			fields = append(fields, marshalled)
		}

		var key VerifyingKey
		key, ok = v.config.Keys[*signatureParams.KeyID]
		if !ok && v.config.KeyResolver != nil {
			if signatureParams.KeyID == nil {
				return errMalformedSignature
			}
			key, err = v.config.KeyResolver.Resolve(*signatureParams.KeyID)
			if err != nil {
				return err
			}
		}
		if v.config.All && key == nil {
			return errUnknownKey
		}
		if key == nil {
			continue
		}

		if signatureParams.Alg != nil && key.GetAlgorithm() != *signatureParams.Alg {
			return errAlgMismatch
		}

		for _, param := range v.config.RequiredParams {
			if _, ok := signatureInput.Params.Get(param); !ok {
				return errMalformedSignature
			}
		}

		for _, field := range v.config.RequiredFields {
			if !slices.Contains(fields, field) {
				return errMalformedSignature
			}
		}

		if signatureParams.Created != nil {
			created := signatureParams.Created.Add(-tolerance)
			// maxAge overrides expires.
			// signature is older than maxAge
			if maxAge != nil && now.Sub(created) > *maxAge || created.After(notAfter) {
				return errSignatureExpired
			}
		}

		if signatureParams.Expires != nil {
			expires := signatureParams.Expires.Add(tolerance)
			// expired signature
			if now.After(expires) {
				return errSignatureExpired
			}
		}

		signingBase, err := createSignatureBase(fields, msg)
		if err != nil {
			return err
		}
		signingBase = append(signingBase, signatureItem{httpsfv.NewItem("@signature-params"), signatureInput})

		base, err := formatSignatureBase(signingBase)
		if err != nil {
			return err
		}

		err = key.Verify([]byte(base), signatureBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

var (
	errNotSigned          = errors.New("signature headers not found")
	errMalformedSignature = errors.New("unable to parse signature headers")
	errUnknownKey         = errors.New("unknown key id")
	errAlgMismatch        = errors.New("algorithm mismatch for key id")
	errSignatureExpired   = errors.New("signature expired")
	errInvalidSignature   = errors.New("invalid signature")
)

type RsaPssSha512VerifyingKey struct {
	*rsa.PublicKey
	KeyID string
}

func (k *RsaPssSha512VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := sha512.New()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)

	return rsa.VerifyPSS(k.PublicKey, crypto.SHA512, bytes, signature, nil)
}

func (k *RsaPssSha512VerifyingKey) GetKeyID() string {
	return k.KeyID
}

func (k *RsaPssSha512VerifyingKey) GetAlgorithm() Algorithm {
	return AlgorithmRsaPssSha512
}

type RsaPkcs1v15Sha256VerifyingKey struct {
	*rsa.PublicKey
	KeyID string
}

func (k *RsaPkcs1v15Sha256VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(k.PublicKey, crypto.SHA512, bytes, signature)
}

func (k *RsaPkcs1v15Sha256VerifyingKey) GetKeyID() string {
	return k.KeyID
}

func (k *RsaPkcs1v15Sha256VerifyingKey) GetAlgorithm() Algorithm {
	return AlgorithmRsaPkcs1v15Sha256
}

type EcdsaP256VerifyingKey struct {
	*ecdsa.PublicKey
	KeyID string
}

func (k *EcdsaP256VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)

	if len(signature) != 64 {
		return errInvalidSignature
	}
	rBytes, sBytes := signature[:32], signature[32:]
	var r, s big.Int
	r.SetBytes(rBytes)
	s.SetBytes(sBytes)

	if !ecdsa.Verify(k.PublicKey, bytes, &r, &s) {
		return errInvalidSignature
	}
	return nil
}

func (k *EcdsaP256VerifyingKey) GetKeyID() string {
	return k.KeyID
}

func (k *EcdsaP256VerifyingKey) GetAlgorithm() Algorithm {
	return AlgorithmEcdsaP256Sha256
}

type EcdsaP384VerifyingKey struct {
	*ecdsa.PublicKey
	KeyID string
}

func (k *EcdsaP384VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := sha512.New384()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)

	if len(signature) != 64 {
		return errInvalidSignature
	}
	rBytes, sBytes := signature[:32], signature[32:]
	var r, s big.Int
	r.SetBytes(rBytes)
	s.SetBytes(sBytes)

	if !ecdsa.Verify(k.PublicKey, bytes, &r, &s) {
		return errInvalidSignature
	}
	return nil
}

func (k *EcdsaP384VerifyingKey) GetKeyID() string {
	return k.KeyID
}

func (k *EcdsaP384VerifyingKey) GetAlgorithm() Algorithm {
	return AlgorithmEcdsaP384Sha384
}

type Ed25519VerifyingKey struct {
	ed25519.PublicKey
	KeyID string
}

func (k *Ed25519VerifyingKey) Verify(data []byte, signature []byte) error {
	if !ed25519.Verify(k.PublicKey, data, signature) {
		return errInvalidSignature
	}
	return nil
}

func (k *Ed25519VerifyingKey) GetKeyID() string {
	return k.KeyID
}

func (k *Ed25519VerifyingKey) GetAlgorithm() Algorithm {
	return AlgorithmEd25519
}

type HmacSha256VerifyingKey struct {
	Secret []byte
	KeyID  string
}

func (k *HmacSha256VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := hmac.New(sha256.New, k.Secret)
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)
	if !hmac.Equal(bytes, signature) {
		return errInvalidSignature
	}
	return nil
}

func (k *HmacSha256VerifyingKey) GetKeyID() string {
	return k.KeyID
}

func (k *HmacSha256VerifyingKey) GetAlgorithm() Algorithm {
	return AlgorithmHmacSha256
}
