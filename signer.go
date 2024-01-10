// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

type SignConfig struct {
	// The key to use for signing
	Key SigningKey

	// The name to try to use for the signature
	// Default: 'sig'
	Name *string

	// The parameters to add to the signature
	// Default: see defaultParams
	Params []Param

	// The HTTP fields / derived component names to sign
	// Default: none
	Fields []string

	// Specified parameter values to use (eg: created time, expires time, etc)
	// This can be used by consumers to override the default expiration time or explicitly opt-out
	// of adding creation time (by setting `created: nil`)
	ParamValues *SignatureParameters
}

type signer struct {
	config SignConfig
}

func updateHeaders(hdr http.Header, config *SignConfig, signature []byte, signatureInput *httpsfv.InnerList) (http.Header, error) {
	var err error

	// check to see if there are already signature/signature-input headers
	// if there are we want to store the current (case-sensitive) name of the header
	// and we want to parse out the current values so we can append our new signature
	signatureHeader, signaturePresent := hdr[SignatureHeader]
	inputHeader, inputPresent := hdr[SignatureInputHeader]

	var signatureHeaderDict *httpsfv.Dictionary
	var inputHeaderDict *httpsfv.Dictionary

	if signaturePresent {
		signatureHeaderDict, err = httpsfv.UnmarshalDictionary(signatureHeader)
		if err != nil {
			return nil, err
		}
	} else {
		signatureHeaderDict = httpsfv.NewDictionary()
	}

	if inputPresent {
		inputHeaderDict, err = httpsfv.UnmarshalDictionary(inputHeader)
		if err != nil {
			return nil, err
		}
	} else {
		inputHeaderDict = httpsfv.NewDictionary()
	}

	// find a unique signature name for the header. Check if any existing headers already use
	// the name we intend to use, if there are, add incrementing numbers to the signature name
	// until we have a unique name to use
	var signatureName string
	if config.Name != nil {
		signatureName = *config.Name
	} else {
		signatureName = "sig"
	}
	count := 1
	_, hasName := signatureHeaderDict.Get(signatureName)
	_, hasInput := inputHeaderDict.Get(signatureName)
	for hasName || hasInput {
		signatureName = fmt.Sprintf("%s%d", signatureName, count)
		_, hasName = signatureHeaderDict.Get(signatureName)
		_, hasInput = inputHeaderDict.Get(signatureName)
		count++
	}

	// append our signature and signature-inputs to the headers and return
	signatureHeaderDict.Add(signatureName, httpsfv.NewItem(signature))
	inputHeaderDict.Add(signatureName, signatureInput)

	marshalledSignatureHeader, err := httpsfv.Marshal(signatureHeaderDict)
	if err != nil {
		return nil, err
	}
	marshalledInputHeader, err := httpsfv.Marshal(inputHeaderDict)
	if err != nil {
		return nil, err
	}

	hdr.Set(SignatureHeader, marshalledSignatureHeader)
	hdr.Set(SignatureInputHeader, marshalledInputHeader)

	return hdr, nil
}

func (s *signer) Sign(msg *Message) (http.Header, error) {
	if s.config.Key == nil {
		return nil, errors.New("signer not configured")
	}

	signingParameters := createSigningParameters(&s.config)
	signatureBase, err := createSignatureBase(s.config.Fields, msg)
	if err != nil {
		return nil, err
	}

	input := httpsfv.InnerList{}
	for _, field := range signatureBase {
		input.Items = append(input.Items, field.key)
	}
	input.Params = signingParameters

	signatureBase = append(signatureBase, signatureItem{httpsfv.NewItem("@signature-params"), input})

	base, err := formatSignatureBase(signatureBase)
	if err != nil {
		return nil, err
	}

	signature, err := s.config.Key.Sign([]byte(base))
	if err != nil {
		return nil, err
	}

	return updateHeaders(msg.Header, &s.config, signature, &input)
}

type RsaPssSha512SigningKey struct {
	*rsa.PrivateKey
	KeyID string
}

func (k *RsaPssSha512SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha512.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := hash.Sum(nil)
	return rsa.SignPSS(rand.Reader, k.PrivateKey, crypto.SHA512, bytes, nil)
}

func (k *RsaPssSha512SigningKey) GetKeyID() string {
	return k.KeyID
}

func (k *RsaPssSha512SigningKey) GetAlgorithm() Algorithm {
	return AlgorithmRsaPssSha512
}

type RsaPkcs1v15Sha256SigningKey struct {
	*rsa.PrivateKey
	KeyID string
}

func (k *RsaPkcs1v15Sha256SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := hash.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, k.PrivateKey, crypto.SHA512, bytes)
}

func (k *RsaPkcs1v15Sha256SigningKey) GetKeyID() string {
	return k.KeyID
}

func (k *RsaPkcs1v15Sha256SigningKey) GetAlgorithm() Algorithm {
	return AlgorithmRsaPkcs1v15Sha256
}

type EcdsaP256SigningKey struct {
	*ecdsa.PrivateKey
	KeyID string
}

func (k *EcdsaP256SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, bytes)
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

func (k *EcdsaP256SigningKey) GetKeyID() string {
	return k.KeyID
}

func (k *EcdsaP256SigningKey) GetAlgorithm() Algorithm {
	return AlgorithmEcdsaP256Sha256
}

type EcdsaP384SigningKey struct {
	*ecdsa.PrivateKey
	KeyID string
}

func (k *EcdsaP384SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha512.New384()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, bytes)
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

func (k *EcdsaP384SigningKey) GetKeyID() string {
	return k.KeyID
}

func (k *EcdsaP384SigningKey) GetAlgorithm() Algorithm {
	return AlgorithmEcdsaP384Sha384
}

type Ed25519SigningKey struct {
	ed25519.PrivateKey
	KeyID string
}

func (k *Ed25519SigningKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(k.PrivateKey, data), nil
}

func (k *Ed25519SigningKey) GetKeyID() string {
	return k.KeyID
}

func (k *Ed25519SigningKey) GetAlgorithm() Algorithm {
	return AlgorithmEd25519
}

type HmacSha256SigningKey struct {
	Secret []byte
	KeyID  string
}

func (k *HmacSha256SigningKey) Sign(data []byte) ([]byte, error) {
	hash := hmac.New(sha256.New, k.Secret)
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (k *HmacSha256SigningKey) GetKeyID() string {
	return k.KeyID
}

func (k *HmacSha256SigningKey) GetAlgorithm() Algorithm {
	return AlgorithmHmacSha256
}

func nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}
