// BSD 3-Clause License

// Copyright (c) 2021, James Bowes
// Copyright (c) 2023, Alexander Taraymovich, OffBlocks
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.

// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.

// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
	"time"

	"github.com/dunglas/httpsfv"
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

// SignConfig is the configuration for a signer
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

// The key to use for signing
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

// NewSigner creates a new signer with the given options
//
// Use the `WithSign*` option funcs to configure signing algorithms and parameters.
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

// Sign signs the given message and returns updated request headers
func (s *Signer) Sign(m *Message) (http.Header, error) {
	return s.signer.Sign(m)
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
