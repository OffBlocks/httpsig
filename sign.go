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
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type sigImpl struct {
	w    io.Writer
	sign func() ([]byte, error)
}

type sigHolder struct {
	alg    string
	nonce  func() *string
	signer func() sigImpl
}

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
	s.keys.Range(func(k, si any) bool {
		sp := &signatureParams{
			items:   items,
			keyID:   k.(string),
			created: now,
			expires: s.expires,
			nonce:   s.nonce,
			alg:     si.(sigHolder).alg,
		}
		sps[fmt.Sprintf("sig%d", i)] = sp.canonicalize()

		signer := si.(sigHolder).signer()
		if _, err := signer.w.Write(b.Bytes()); err != nil {
			panic(err)
		}

		if err := canonicalizeSignatureParams(signer.w, sp); err != nil {
			panic(err)
		}

		signed, err := signer.sign()
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

func signRsaPssSha512(pk *rsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "rsa-pss-sha512",
		nonce: func() *string {
			n := nonce()
			return &n
		},
		signer: func() sigImpl {
			h := sha512.New()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					b := h.Sum(nil)
					return rsa.SignPSS(rand.Reader, pk, crypto.SHA512, b, nil)
				},
			}
		},
	}
}

func signRsaPkcs1v15Sha256(pk *rsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "rsa-v1_5-sha256",
		nonce: func() *string {
			n := nonce()
			return &n
		},
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					b := h.Sum(nil)
					return rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA512, b)
				},
			}
		},
	}
}

func signEccP256(pk *ecdsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "ecdsa-p256-sha256",
		nonce: func() *string {
			n := nonce()
			return &n
		},
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					b := h.Sum(nil)
					return ecdsa.SignASN1(rand.Reader, pk, b)
				},
			}
		},
	}
}

func signEccP384(pk *ecdsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "ecdsa-p384-sha384",
		nonce: func() *string {
			n := nonce()
			return &n
		},
		signer: func() sigImpl {
			h := sha512.New384()

			return sigImpl{
				w: h,
				sign: func() ([]byte, error) {
					b := h.Sum(nil)
					return ecdsa.SignASN1(rand.Reader, pk, b)
				},
			}
		},
	}
}

func signEd25519(pk *ed25519.PrivateKey) sigHolder {
	return sigHolder{
		alg: "ed25519",
		nonce: func() *string {
			n := nonce()
			return &n
		},
		signer: func() sigImpl {
			var h bytes.Buffer

			return sigImpl{
				w: &h,
				sign: func() ([]byte, error) {
					b := h.Bytes()
					return ed25519.Sign(*pk, b), nil
				},
			}
		},
	}
}

func signHmacSha256(secret []byte) sigHolder {
	return sigHolder{
		alg: "hmac-sha256",
		signer: func() sigImpl {
			h := hmac.New(sha256.New, secret)

			return sigImpl{
				w:    h,
				sign: func() ([]byte, error) { return h.Sum(nil), nil },
			}
		},
	}
}

func nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return base64.URLEncoding.EncodeToString(b)
}
