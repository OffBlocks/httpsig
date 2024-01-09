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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type signer struct {
	headers []string
	keys    sync.Map

	created *time.Time
	expires *time.Time
	nonce   *string
}

func withCreated(t time.Time) signOption {
	return &optImpl{
		s: func(s *signer) { s.created = &t },
	}
}

func withNonce(nonce string) signOption {
	return &optImpl{
		s: func(s *signer) { s.nonce = &nonce },
	}
}

func (s *signer) Sign(msg *message) (http.Header, error) {
	var b bytes.Buffer

	var items []string

	// canonicalize headers
	for _, h := range s.headers {
		// Skip unset headers
		if len(h) > 0 && h[0] != '@' && len(msg.Header.Values(h)) == 0 {
			continue
		}

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
			return nil, err
		}

		items = append(items, h)
	}

	var now time.Time
	if s.created != nil {
		now = *s.created
	} else {
		now = time.Now()
	}

	sps := make(map[string]string)
	sigs := make(map[string]string)
	i := 1 // 1 indexed icky
	s.keys.Range(func(k, sk any) bool {
		key := sk.(SigningKey)

		sp := &signatureParams{
			items:   items,
			keyID:   k.(string),
			created: now,
			expires: s.expires,
			nonce:   s.nonce,
			alg:     key.Algorithm(),
		}
		sps[fmt.Sprintf("sig%d", i)] = sp.canonicalize()

		var w bytes.Buffer

		if _, err := w.Write(b.Bytes()); err != nil {
			panic(err)
		}

		if err := canonicalizeSignatureParams(&w, sp); err != nil {
			panic(err)
		}

		signed, err := key.Sign(w.Bytes())
		if err != nil {
			panic(err)
		}

		sigs[fmt.Sprintf("sig%d", i)] = base64.StdEncoding.EncodeToString(signed)

		i++

		return true
	})

	// for each configured key id,
	// canonicalize signing options appended to byte slice
	// create signature

	// add new headers with params for all key ids and signatures

	// TODO: make this stable
	var parts []string
	var sigparts []string
	for k, v := range sps {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		sigparts = append(sigparts, fmt.Sprintf("%s=:%s:", k, sigs[k]))
	}

	hdr := make(http.Header)
	hdr.Set("signature-input", strings.Join(parts, ", "))
	hdr.Set("signature", strings.Join(sigparts, ", "))

	return hdr, nil
}

type RsaPssSha512SigningKey struct {
	*rsa.PrivateKey
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

func (k *RsaPssSha512SigningKey) Algorithm() Algorithm {
	return AlgorithmRsaPssSha512
}

func (k *RsaPssSha512SigningKey) Nonce() *string {
	n := nonce()
	return &n
}

type RsaPkcs1v15Sha256SigningKey struct {
	*rsa.PrivateKey
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

func (k *RsaPkcs1v15Sha256SigningKey) Algorithm() Algorithm {
	return AlgorithmRsaPkcs1v15Sha256
}

func (k *RsaPkcs1v15Sha256SigningKey) Nonce() *string {
	n := nonce()
	return &n
}

type EcdsaP256SigningKey struct {
	*ecdsa.PrivateKey
}

func (k *EcdsaP256SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := hash.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, k.PrivateKey, bytes)
}

func (k *EcdsaP256SigningKey) Algorithm() Algorithm {
	return AlgorithmEcdsaP256Sha256
}

func (k *EcdsaP256SigningKey) Nonce() *string {
	n := nonce()
	return &n
}

type EcdsaP384SigningKey struct {
	*ecdsa.PrivateKey
}

func (k *EcdsaP384SigningKey) Sign(data []byte) ([]byte, error) {
	hash := sha512.New384()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	bytes := hash.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, k.PrivateKey, bytes)
}

func (k *EcdsaP384SigningKey) Algorithm() Algorithm {
	return AlgorithmEcdsaP384Sha384
}

func (k *EcdsaP384SigningKey) Nonce() *string {
	n := nonce()
	return &n
}

type Ed25519SigningKey struct {
	ed25519.PrivateKey
}

func (k *Ed25519SigningKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(k.PrivateKey, data), nil
}

func (k *Ed25519SigningKey) Algorithm() Algorithm {
	return AlgorithmEd25519
}

func (k *Ed25519SigningKey) Nonce() *string {
	n := nonce()
	return &n
}

type HmacSha256SigningKey struct {
	Secret []byte
}

func (k *HmacSha256SigningKey) Sign(data []byte) ([]byte, error) {
	hash := hmac.New(sha256.New, k.Secret)
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (k *HmacSha256SigningKey) Algorithm() Algorithm {
	return AlgorithmHmacSha256
}

func (k *HmacSha256SigningKey) Nonce() *string {
	return nil
}

func nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}
