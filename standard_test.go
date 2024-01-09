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

func testReq() *message {
	return &message{
		Method:    "POST",
		Authority: "example.com",
		URL:       parse("https://example.com/foo?param=value&pet=dog"),
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
			"Content-Length": []string{"18"},
		},
	}
}

func TestSign_RSA_PSS_SHA_512_Minimal_B_2_1(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSS))
	if block == nil {
		panic("could not decode test private key pem")
	}

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		panic("could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	s := signer{}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-rsa-pss", signRsaPssSha512(pk))

	hdr, err := s.Sign(testReq())
	if err != nil {
		t.Error("signing failed:", err)
	}

	if hdr.Get("Signature-Input") != `sig1=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd";alg="rsa-pss-sha512"` {
		t.Error("signature input did not match. Got:", hdr.Get("Signature-Input"))
	}

	// can't verify signature as it is randomised
}

func TestVerify_RSA_PSS_SHA_512_Minimal_B_2_1(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pk := pki.(*rsa.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}
	v.keys.Store("test-key-rsa-pss", verifyRsaPssSha512(pk))

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`)
	req.Header.Set("Signature", `sig1=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`)

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestRoundtrip_RSA_PSS_SHA_512_Minimal_B_2_1(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyRSAPSS))
	if blockPrivate == nil {
		panic("could not decode test private key pem")
	}

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(blockPrivate.Bytes, &privKey); err != nil {
		panic("could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	s := signer{}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-rsa-pss", signRsaPssSha512(pk))

	req := testReq()
	hdr, err := s.Sign(req)
	if err != nil {
		t.Error("signing failed:", err)
	}

	blockPub, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if blockPub == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pubk := pki.(*rsa.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}
	v.keys.Store("test-key-rsa-pss", verifyRsaPssSha512(pubk))

	req.Header.Set("Signature-Input", hdr["Signature-Input"][0])
	req.Header.Set("Signature", hdr["Signature"][0])

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestSign_RSA_PSS_SHA_512_Selective_B_2_2(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSS))
	if block == nil {
		panic("could not decode test private key pem")
	}

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		panic("could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	s := signer{
		headers: []string{"@authority", "content-digest"},
	}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-rsa-pss", signRsaPssSha512(pk))

	hdr, err := s.Sign(testReq())
	if err != nil {
		t.Error("signing failed:", err)
	}

	if hdr.Get("Signature-Input") != `sig1=("@authority" "content-digest");created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd";alg="rsa-pss-sha512"` {
		t.Error("signature input did not match. Got:", hdr.Get("Signature-Input"))
	}

	// can't verify signature as it is randomised
}

func TestVerify_RSA_PSS_SHA_512_Selective_B_2_2(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pk := pki.(*rsa.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884473, 0) },
	}
	v.keys.Store("test-key-rsa-pss", verifyRsaPssSha512(pk))

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=("@authority" "content-digest");created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd";alg="rsa-pss-sha512"`)
	req.Header.Set("Signature", `sig1=:e7vSoRHcw4hxLAp129Qdxui1KTgTnI8LM8/gNK7PZJwWm/HCcz+Mxwrzs97fNVCeiu0XPjtPdUcc5mz6/rD644aj0FpvSZzRhlP3KLBU8QMCI80m8blQhDBQeVR/XX9CGLD9BSgWPmd9J4FOf1b/giseT6dbxof1gVvZbHBVPurIGVyht7kNDUTLzxPEFlm7hQBKz0U5UCuqm4Fxw1jRaFm5WhWHwU1A3iqgf7QqE1HT+bCn/MCPl9KstKY5XgKDnJjGA0+qDfFrsNpii1hx/GNsAPWfcJnc7NjASfXtkyItr1e0Wqk2c2gpejiTxW7Qu9mYUmODBiCDn75rK9hSyQ==:`)

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestRoundtrip_RSA_PSS_SHA_512_Selective_B_2_2(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyRSAPSS))
	if blockPrivate == nil {
		panic("could not decode test private key pem")
	}

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(blockPrivate.Bytes, &privKey); err != nil {
		panic("could not decode test private key pem")
	}

	pk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	s := signer{
		headers: []string{"@authority", "content-digest"},
	}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-rsa-pss", signRsaPssSha512(pk))

	req := testReq()
	hdr, err := s.Sign(req)
	if err != nil {
		t.Error("signing failed:", err)
	}

	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pkpub := pki.(*rsa.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884473, 0) },
	}
	v.keys.Store("test-key-rsa-pss", verifyRsaPssSha512(pkpub))

	req.Header.Set("Signature-Input", hdr["Signature-Input"][0])
	req.Header.Set("Signature", hdr["Signature"][0])

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestRoundtrip_ECDSA_P256_SHA256(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyECCP256))
	if blockPrivate == nil {
		panic("could not decode test private key pem")
	}

	pk, err := x509.ParseECPrivateKey(blockPrivate.Bytes)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	s := signer{}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-ecc-p256", signEccP256(pk))

	req := testReq()
	hdr, err := s.Sign(req)
	if err != nil {
		t.Error("signing failed:", err)
	}

	block, _ := pem.Decode([]byte(testKeyECCP256Pub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pkpub := pki.(*ecdsa.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884473, 0) },
	}
	v.keys.Store("test-key-ecc-p256", verifyEccP256(pkpub))

	req.Header.Set("Signature-Input", hdr["Signature-Input"][0])
	req.Header.Set("Signature", hdr["Signature"][0])

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestRoundtrip_ECDSA_P384_SHA384(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyECCP384))
	if blockPrivate == nil {
		panic("could not decode test private key pem")
	}

	pk, err := x509.ParseECPrivateKey(blockPrivate.Bytes)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	s := signer{}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-ecc-p384", signEccP384(pk))

	req := testReq()
	hdr, err := s.Sign(req)
	if err != nil {
		t.Error("signing failed:", err)
	}

	block, _ := pem.Decode([]byte(testKeyECCP384Pub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pkpub := pki.(*ecdsa.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884473, 0) },
	}
	v.keys.Store("test-key-ecc-p384", verifyEccP384(pkpub))

	req.Header.Set("Signature-Input", hdr["Signature-Input"][0])
	req.Header.Set("Signature", hdr["Signature"][0])

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestRoundtrip_ED25519(t *testing.T) {
	blockPrivate, _ := pem.Decode([]byte(testKeyEd25519))
	if blockPrivate == nil {
		panic("could not decode test private key pem")
	}

	pki, err := x509.ParsePKCS8PrivateKey(blockPrivate.Bytes)
	if err != nil {
		panic("could not decode test private key: " + err.Error())
	}

	pk := pki.(ed25519.PrivateKey)

	s := signer{}
	withCreated(time.Unix(1618884473, 0)).configureSign(&s)
	withNonce("b3k2pp5k7z-50gnwp.yemd").configureSign(&s)

	s.keys.Store("test-key-ed25519", signEd25519(&pk))

	req := testReq()
	hdr, err := s.Sign(req)
	if err != nil {
		t.Error("signing failed:", err)
	}

	block, _ := pem.Decode([]byte(testKeyEd25519Pub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pkpubi, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pkpub := pkpubi.(ed25519.PublicKey)

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884473, 0) },
	}
	v.keys.Store("test-key-ed25519", verifyEd25519(&pkpub))

	req.Header.Set("Signature-Input", hdr["Signature-Input"][0])
	req.Header.Set("Signature", hdr["Signature"][0])

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestSign_HMAC_SHA_256_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	s := signer{
		headers: []string{"@authority", "date", "content-type"},
	}
	withCreated(time.Unix(1618884475, 0)).configureSign(&s)

	s.keys.Store("test-shared-secret", signHmacSha256(k))

	hdr, err := s.Sign(testReq())
	if err != nil {
		t.Error("signing failed:", err)
	}

	if hdr.Get("Signature-Input") != `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret";alg="hmac-sha256"` {
		t.Error("signature input did not match. Got:", hdr.Get("Signature-Input"))
	}

	if hdr.Get("Signature") != `sig1=:Ss67se+mIHEQhqCYpEpp521HLd+2KuQyXRtHr1RfIRk=:` {
		t.Error("signature did not match. Got:", hdr.Get("Signature"))
	}
}

func TestVerify_HMAC_SHA_256_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}
	v.keys.Store("test-shared-secret", verifyHmacSha256(k))

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret"`)
	req.Header.Set("Signature", `sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:`)

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestRoundtrip_HMAC_SHA_256_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	s := signer{
		headers: []string{"@authority", "date", "content-type"},
	}
	withCreated(time.Unix(1618884475, 0)).configureSign(&s)

	s.keys.Store("test-shared-secret", signHmacSha256(k))

	req := testReq()
	hdr, err := s.Sign(req)
	if err != nil {
		t.Error("signing failed:", err)
	}

	v := &verifier{
		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}
	v.keys.Store("test-shared-secret", verifyHmacSha256(k))

	req.Header.Set("Signature-Input", hdr["Signature-Input"][0])
	req.Header.Set("Signature", hdr["Signature"][0])

	_, err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
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

var testKeyECCP384Pub = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUWosCCtXp4eJkinU2XaDGSrrSfMynZkI
EELa7Ratog6SrkIFD9nowhLoxc3Px4zAwxQzD8j5Th+vCtswq7ExACNiM6kM9974
mF1l1Ll2Pn19pJCE2SutyxcMeAr4Lrgi
-----END PUBLIC KEY-----
`

var testKeyECCP384 = `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDayXurkt5pieok3TsD5CdPvrUgljTE8n5o9M1bapc8yMz94WCAiQZb
TXi9MwOv4TWgBwYFK4EEACKhZANiAARRaiwIK1enh4mSKdTZdoMZKutJ8zKdmQgQ
QtrtFq2iDpKuQgUP2ejCEujFzc/HjMDDFDMPyPlOH68K2zCrsTEAI2IzqQz33viY
XWXUuXY+fX2kkITZK63LFwx4CvguuCI=
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
