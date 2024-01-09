// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type verifier struct {
	keys     sync.Map
	resolver VerifyingKeyResolver

	// For testing
	nowFunc func() time.Time
}

// XXX: note about fail fast.
func (v *verifier) Verify(msg *message) (keyID string, err error) {
	sigHdr := msg.Header.Get("Signature")
	if sigHdr == "" {
		return "", errNotSigned
	}

	paramHdr := msg.Header.Get("Signature-Input")
	if paramHdr == "" {
		return "", errNotSigned
	}

	sigParts := strings.Split(sigHdr, ", ")
	paramParts := strings.Split(paramHdr, ", ")

	if len(sigParts) != len(paramParts) {
		return "", errMalformedSignature
	}

	// TODO: could be smarter about selecting the sig to verify, eg based
	// on algorithm
	var sigID string
	var params *signatureParams
	var paramsRaw string
	for _, p := range paramParts {
		pParts := strings.SplitN(p, "=", 2)
		if len(pParts) != 2 {
			return "", errMalformedSignature
		}

		candidate, err := parseSignatureInput(pParts[1])
		if err != nil {
			return "", errMalformedSignature
		}

		if _, err := v.ResolveKey(candidate.keyID, candidate.alg); err == nil {
			sigID = pParts[0]
			params = candidate
			paramsRaw = pParts[1]
			break
		}
	}

	if params == nil {
		return "", errUnknownKey
	}

	var signature string
	for _, s := range sigParts {
		sParts := strings.SplitN(s, "=", 2)
		if len(sParts) != 2 {
			return params.keyID, errMalformedSignature
		}

		if sParts[0] == sigID {
			// TODO: error if not surrounded by colons
			signature = strings.Trim(sParts[1], ":")
			break
		}
	}

	if signature == "" {
		return params.keyID, errMalformedSignature
	}

	ver, err := v.ResolveKey(params.keyID, params.alg)
	if err != nil {
		return params.keyID, err
	}

	if params.alg != "" && ver.Algorithm() != params.alg {
		return params.keyID, errAlgMismatch
	}

	// verify signature. if invalid, error
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return params.keyID, errMalformedSignature
	}

	//TODO: skip the buffer.

	var b bytes.Buffer

	// canonicalize headers
	// TODO: wrap the errors within
	for _, h := range params.items {

		// handle specialty components, section 2.3
		var err error
		switch h {
		case "@method":
			err = canonicalizeMethod(&b, msg.Method)
		case "@path":
			err = canonicalizePath(&b, msg.URL.Path)
		case "@query":
			err = canonicalizeQuery(&b, msg.URL.RawQuery)
		case "@authority":
			err = canonicalizeAuthority(&b, msg.Authority)
		default:
			// handle default (header) components
			err = canonicalizeHeader(&b, h, msg.Header)
		}

		if err != nil {
			return params.keyID, err
		}
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", paramsRaw)

	err = ver.Verify(b.Bytes(), sig)
	if err != nil {
		return params.keyID, errInvalidSignature
	}

	// TODO: could put in some wiggle room
	if params.expires != nil && params.expires.After(time.Now()) {
		return params.keyID, errSignatureExpired
	}

	return params.keyID, nil
}

func (v *verifier) ResolveKey(keyID string, alg Algorithm) (VerifyingKey, error) {
	if key, ok := v.keys.Load(keyID); ok {
		return key.(VerifyingKey), nil
	}

	if v.resolver != nil {
		key, err := v.resolver.Resolve(keyID, alg)
		if err != nil {
			return nil, err
		}
		v.keys.Store(keyID, key)
		return key, nil
	}

	return nil, errUnknownKey
}

// XXX use vice here too.

var (
	errNotSigned          = errors.New("signature headers not found")
	errMalformedSignature = errors.New("unable to parse signature headers")
	errUnknownKey         = errors.New("unknown key id")
	errAlgMismatch        = errors.New("algorithm mismatch for key id")
	errSignatureExpired   = errors.New("signature expired")
	errInvalidSignature   = errors.New("invalid signature")
)

// These error checking funcs aren't needed yet, so don't export them

/*

func IsNotSignedError(err error) bool          { return errors.Is(err, notSignedError) }
func IsMalformedSignatureError(err error) bool { return errors.Is(err, malformedSignatureError) }
func IsUnknownKeyError(err error) bool         { return errors.Is(err, unknownKeyError) }
func IsAlgMismatchError(err error) bool        { return errors.Is(err, algMismatchError) }
func IsSignatureExpiredError(err error) bool   { return errors.Is(err, signatureExpiredError) }
func IsInvalidSignatureError(err error) bool   { return errors.Is(err, invalidSignatureError) }

*/

type RsaPssSha512VerifyingKey struct {
	*rsa.PublicKey
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

func (k *RsaPssSha512VerifyingKey) Algorithm() Algorithm {
	return AlgorithmRsaPssSha512
}

type RsaPkcs1v15Sha256VerifyingKey struct {
	*rsa.PublicKey
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

func (k *RsaPkcs1v15Sha256VerifyingKey) Algorithm() Algorithm {
	return AlgorithmRsaPkcs1v15Sha256
}

type EcdsaP256VerifyingKey struct {
	*ecdsa.PublicKey
}

func (k *EcdsaP256VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)

	if !ecdsa.VerifyASN1(k.PublicKey, bytes, signature) {
		return errInvalidSignature
	}
	return nil
}

func (k *EcdsaP256VerifyingKey) Algorithm() Algorithm {
	return AlgorithmEcdsaP256Sha256
}

type EcdsaP384VerifyingKey struct {
	*ecdsa.PublicKey
}

func (k *EcdsaP384VerifyingKey) Verify(data []byte, signature []byte) error {
	hash := sha512.New384()
	_, err := hash.Write(data)
	if err != nil {
		return err
	}

	bytes := hash.Sum(nil)

	if !ecdsa.VerifyASN1(k.PublicKey, bytes, signature) {
		return errInvalidSignature
	}
	return nil
}

func (k *EcdsaP384VerifyingKey) Algorithm() Algorithm {
	return AlgorithmEcdsaP384Sha384
}

type Ed25519VerifyingKey struct {
	ed25519.PublicKey
}

func (k *Ed25519VerifyingKey) Verify(data []byte, signature []byte) error {
	if !ed25519.Verify(k.PublicKey, data, signature) {
		return errInvalidSignature
	}
	return nil
}

func (k *Ed25519VerifyingKey) Algorithm() Algorithm {
	return AlgorithmEd25519
}

type HmacSha256VerifyingKey struct {
	Secret []byte
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

func (k *HmacSha256VerifyingKey) Algorithm() Algorithm {
	return AlgorithmHmacSha256
}
