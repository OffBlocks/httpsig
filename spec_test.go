// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// These tests come from the sample data in the draft standard.
// Most of the signing tests aren't applicable, as the signatures contain some randomness.
// B_*_* map to sections in the standard.

func parse(in string) *url.URL {
	out, err := url.Parse(in)
	if err != nil {
		panic("couldn't parse static url for test!")
	}
	return out
}

type testClock struct {
	now time.Time
}

func (t *testClock) Now() time.Time {
	return t.now
}

func withClock(clock clock) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.clock = clock },
	}
}

func testReq() *http.Request {
	return &http.Request{
		Method: "POST",
		Host:   "example.com",
		URL:    parse("https://example.com/foo?param=Value&Pet=dog"),
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
			"Content-Length": []string{"18"},
		},
		ContentLength: 18,
	}
}

func testResp() *http.Response {
	req := testReq()
	return &http.Response{
		Request:    req,
		StatusCode: 200,
		Header: http.Header{
			"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Digest": []string{"sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"},
			"Content-Length": []string{"23"},
		},
		ContentLength: 18,
	}
}

func TestSign_RSA_PSS_SHA_512_Minimal_B_2_1(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSS))
	assert.NotNil(t, block, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		assert.NoError(t, err, "could not decode test private key")
	}

	created := time.Unix(1618884473, 0)
	nonce := "b3k2pp5k7z-50gnwp.yemd"
	s := NewSigner(
		WithSignName("sig-b21"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
			ParamNonce,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
			Nonce:   &nonce,
		}),
		WithSignRsaPssSha512("test-key-rsa-pss", pk),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")

	assert.Equal(t, `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`, hdr.Get("Signature-Input"), "signature input did not match")

	// can't verify signature as it is randomised
}

func TestVerify_RSA_PSS_SHA_512_Minimal_B_2_1(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pk := pki.(*rsa.PublicKey)

	v := NewVerifier(
		WithVerifyRsaPssSha512("test-key-rsa-pss", pk),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	req := testReq()
	req.Header.Set("Signature-Input", `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`)
	req.Header.Set("Signature", `sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestRoundtrip_RSA_PSS_SHA_512_Minimal_B_2_1(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyRSAPSS))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(blockPrivate.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	nonce := "b3k2pp5k7z-50gnwp.yemd"
	s := NewSigner(
		WithSignName("sig-b21"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
			ParamNonce,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
			Nonce:   &nonce,
		}),
		WithSignRsaPssSha512("test-key-rsa-pss", pk),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")
	req.Header = hdr

	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pkpub := pki.(*rsa.PublicKey)

	v := NewVerifier(
		WithVerifyRsaPssSha512("test-key-rsa-pss", pkpub),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestSign_RSA_PSS_SHA_512_Selective_B_2_2(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSS))
	assert.NotNil(t, block, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	nonce := "b3k2pp5k7z-50gnwp.yemd"
	tag := "header-example"
	s := NewSigner(
		WithSignName("sig-b22"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
			ParamNonce,
			ParamTag,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
			Nonce:   &nonce,
			Tag:     &tag,
		}),
		WithSignRsaPssSha512("test-key-rsa-pss", pk),
		WithSignFields("@authority", "content-digest", "@query-param;name=\"Pet\""),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")

	assert.Equal(t, `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd";tag="header-example"`, hdr.Get("Signature-Input"), "signature input did not match")

	// can't verify signature as it is randomised
}

func TestVerify_RSA_PSS_SHA_512_Selective_B_2_2(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pk := pki.(*rsa.PublicKey)

	v := NewVerifier(
		WithVerifyRsaPssSha512("test-key-rsa-pss", pk),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	req := testReq()
	req.Header.Set("Signature-Input", `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`)
	req.Header.Set("Signature", `sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:`)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestRoundtrip_RSA_PSS_SHA_512_Selective_B_2_2(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyRSAPSS))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(blockPrivate.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	nonce := "b3k2pp5k7z-50gnwp.yemd"
	tag := "header-example"
	s := NewSigner(
		WithSignName("sig-b22"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
			ParamNonce,
			ParamTag,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
			Nonce:   &nonce,
			Tag:     &tag,
		}),
		WithSignRsaPssSha512("test-key-rsa-pss", pk),
		WithSignFields("@authority", "content-digest", "@query-param;name=\"Pet\""),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")
	req.Header = hdr

	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pkpub := pki.(*rsa.PublicKey)

	v := NewVerifier(
		WithVerifyRsaPssSha512("test-key-rsa-pss", pkpub),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestSign_RSA_PSS_SHA_512_Full_Coverage_B_2_3(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSS))
	assert.NotNil(t, block, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b23"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithSignRsaPssSha512("test-key-rsa-pss", pk),
		WithSignFields("date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length"),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")

	assert.Equal(t, `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`, hdr.Get("Signature-Input"), "signature input did not match")

	// can't verify signature as it is randomised
}

func TestVerify_RSA_PSS_SHA_512_Full_Coverage_B_2_3(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pk := pki.(*rsa.PublicKey)

	v := NewVerifier(
		WithVerifyRsaPssSha512("test-key-rsa-pss", pk),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	req := testReq()
	req.Header.Set("Signature-Input", `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", `sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:`)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestRoundtrip_RSA_PSS_SHA_512_Full_Coverage_B_2_3(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyRSAPSS))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(blockPrivate.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b23"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithSignRsaPssSha512("test-key-rsa-pss", pk),
		WithSignFields("date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length"),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")
	req.Header = hdr

	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pkpub := pki.(*rsa.PublicKey)

	v := NewVerifier(
		WithVerifyRsaPssSha512("test-key-rsa-pss", pkpub),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestSign_ECDSA_P256_SHA256_B_2_4(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyECCP256))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	pk, err := x509.ParseECPrivateKey(blockPrivate.Bytes)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b24"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithSignEcdsaP256Sha256("test-key-ecc-p256", pk),
		WithSignFields("@status", "content-type", "content-digest", "content-length"),
	)

	resp := testResp()
	hdr, err := s.Sign(MessageFromResponse(resp))
	assert.NoError(t, err, "signing failed")

	assert.Equal(t, `sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`, hdr.Get("Signature-Input"), "signature input did not match")

	// can't verify signature as it is randomised
}

func TestVerify_ECDSA_P256_SHA256_B_2_4(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyECCP256Pub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pk := pki.(*ecdsa.PublicKey)

	v := NewVerifier(
		WithVerifyEcdsaP256Sha256("test-key-ecc-p256", pk),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	resp := testResp()
	resp.Header.Set("Signature-Input", `sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`)
	resp.Header.Set("Signature", `sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:`)

	assert.NoError(t, v.Verify(MessageFromResponse(resp)), "verification failed")
}

func TestRoundtrip_ECDSA_P256_SHA256_B_2_4(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyECCP256))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	pk, err := x509.ParseECPrivateKey(blockPrivate.Bytes)
	assert.NoError(t, err, "could not decode test private key")

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b24"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithSignEcdsaP256Sha256("test-key-ecc-p256", pk),
		WithSignFields("@status", "content-type", "content-digest", "content-length"),
	)

	resp := testResp()
	hdr, err := s.Sign(MessageFromResponse(resp))
	assert.NoError(t, err, "signing failed")
	resp.Header = hdr

	block, _ := pem.Decode([]byte(testKeyECCP256Pub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pkpub := pki.(*ecdsa.PublicKey)

	v := NewVerifier(
		WithVerifyEcdsaP256Sha256("test-key-ecc-p256", pkpub),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	assert.NoError(t, v.Verify(MessageFromResponse(resp)), "verification failed")
}

func TestSign_HMAC_SHA_256_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b25"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithHmacSha256("test-shared-secret", k),
		WithSignFields("date", "@authority", "content-type"),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")

	assert.Equal(t, `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`, hdr.Get("Signature-Input"), "signature input did not match")

	// can't verify signature as it is randomised
}

func TestVerify_HMAC_SHA_256_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	v := NewVerifier(
		WithHmacSha256("test-shared-secret", k),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	req := testReq()
	req.Header.Set("Signature-Input", `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`)
	req.Header.Set("Signature", `sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:`)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestRoundtrip_HMAC_SHA_256_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b25"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithHmacSha256("test-shared-secret", k),
		WithSignFields("date", "@authority", "content-type"),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")
	req.Header = hdr

	v := NewVerifier(
		WithHmacSha256("test-shared-secret", k),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestSign_ED25519_B_2_6(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyEd25519))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	pki, err := x509.ParsePKCS8PrivateKey(blockPrivate.Bytes)
	assert.NoError(t, err, "could not decode test private key")

	pk := pki.(ed25519.PrivateKey)

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b26"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithSignEd25519("test-key-ed25519", pk),
		WithSignFields("date", "@method", "@path", "@authority", "content-type", "content-length"),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")

	assert.Equal(t, `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`, hdr.Get("Signature-Input"), "signature input did not match")

	// can't verify signature as it is randomised
}

func TestVerify_ED25519_B_2_6(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyEd25519Pub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pk := pki.(ed25519.PublicKey)

	v := NewVerifier(
		WithVerifyEd25519("test-key-ed25519", pk),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	req := testReq()
	req.Header.Set("Signature-Input", `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`)
	req.Header.Set("Signature", `sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

func TestRoundtrip_ED25519_B_2_6(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyEd25519))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	pki, err := x509.ParsePKCS8PrivateKey(blockPrivate.Bytes)
	assert.NoError(t, err, "could not decode test private key")

	pk := pki.(ed25519.PrivateKey)

	created := time.Unix(1618884473, 0)
	s := NewSigner(
		WithSignName("sig-b26"),
		WithSignParams(
			ParamCreated,
			ParamKeyID,
		),
		WithSignParamValues(&SignatureParameters{
			Created: &created,
		}),
		WithSignEd25519("test-key-ed25519", pk),
		WithSignFields("date", "@method", "@path", "@authority", "content-type", "content-length"),
	)

	req := testReq()
	hdr, err := s.Sign(MessageFromRequest(req))
	assert.NoError(t, err, "signing failed")
	req.Header = hdr

	block, _ := pem.Decode([]byte(testKeyEd25519Pub))
	assert.NotNil(t, block, "could not decode test public key pem")

	pki, err = x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "could not decode test public key")

	pkpub := pki.(ed25519.PublicKey)

	v := NewVerifier(
		WithVerifyEd25519("test-key-ed25519", pkpub),
		withClock(&testClock{now: time.Unix(1618884473, 0)}),
	)

	assert.NoError(t, v.Verify(MessageFromRequest(req)), "verification failed")
}

// The following keypairs are taken from the Draft Standard, so we may recreate the examples in tests.
// If your robot scans this repo and says it's leaking keys I will be mildly amused.

var testKeyRSAPSSPub = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
`

var testKeyRSAPSS = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----
`

var testKeyECCP256Pub = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
`

var testKeyECCP256 = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
`

var testKeyEd25519Pub = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
`

var testKeyEd25519 = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----
`

var testSharedSecret = `uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==`
