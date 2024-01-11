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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"time"
)

type signOption interface {
	configureSign(s *signer)
}

type verifyOption interface {
	configureVerify(v *verifier)
}

type digestOption interface {
	configureDigest(d *digestor)
}

type signOrVerifyOption interface {
	signOption
	verifyOption
}

type optImpl struct {
	s func(s *signer)
	v func(v *verifier)
	d func(d *digestor)
}

func (o *optImpl) configureSign(s *signer)     { o.s(s) }
func (o *optImpl) configureVerify(v *verifier) { o.v(v) }
func (o *optImpl) configureDigest(d *digestor) { o.d(d) }

// WithSignName sets the name of the signature to be used for signing.
// default: "sig"
func WithSignName(name string) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Name = &name },
	}
}

// WithSignParams sets the signature parameters to be included in signing.
// default: created, keyid, alg
func WithSignParams(params ...Param) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Params = params },
	}
}

// WithSignFields sets the HTTP fields / derived component names to be included in signing.
// default: none
func WithSignFields(fields ...string) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Fields = fields },
	}
}

// WithSignParamValues sets the signature parameters to be included in signing.
func WithSignParamValues(params *SignatureParameters) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.ParamValues = params },
	}
}

// WithSignRsaPkcs1v15Sha256 adds signing using `rsa-v1_5-sha256` with the given private key
// using the given key id.
func WithSignRsaPkcs1v15Sha256(keyID string, pk *rsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Key = &RsaPkcs1v15Sha256SigningKey{pk, keyID} },
	}
}

// WithSignRsaPssSha512 adds signing using `rsa-pss-sha512` with the given private key
// using the given key id.
func WithSignRsaPssSha512(keyID string, pk *rsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Key = &RsaPssSha512SigningKey{pk, keyID} },
	}
}

// WithSignEcdsaP256Sha256 adds signing using `ecdsa-p256-sha256` with the given private key
// using the given key id.
func WithSignEcdsaP256Sha256(keyID string, pk *ecdsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Key = &EcdsaP256SigningKey{pk, keyID} },
	}
}

// WithSignEcdsaP384Sha384 adds signing using `ecdsa-p384-sha384` with the given private key
// using the given key id.
func WithSignEcdsaP384Sha384(keyID string, pk *ecdsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Key = &EcdsaP384SigningKey{pk, keyID} },
	}
}

// WithSignEd25519 adds signing using `ed25519` with the given private key
// using the given key id.
func WithSignEd25519(keyID string, pk ed25519.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.config.Key = &Ed25519SigningKey{pk, keyID} },
	}
}

// WithVerifyingKeyResolver sets the resolver to use for verifying keys.
func WithVerifyingKeyResolver(resolver VerifyingKeyResolver) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.KeyResolver = resolver },
	}
}

// WithVerifyNotAfter sets the time after which signatures are considered expired.
// default: time.Now() + 5 mins
func WithVerifyNotAfter(t time.Time) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.NotAfter = &t },
	}
}

// WithVerifyMaxAge sets the maximum age of a signature.
// default: 0
func WithVerifyMaxAge(d time.Duration) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.MaxAge = &d },
	}
}

// WithVerifyTolerance sets the clock tolerance for verifying created and expires times.
// default: 0
func WithVerifyTolerance(d time.Duration) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.Tolerance = &d },
	}
}

// WithVerifyRequiredParams sets the required signature parameters.
// default: []
func WithVerifyRequiredParams(params ...string) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.RequiredParams = params },
	}
}

// WithVerifyRequiredFields sets the required HTTP fields / derived component names.
// default: []
func WithVerifyRequiredFields(fields ...string) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.RequiredFields = fields },
	}
}

// WithVerifyAll sets whether all signatures must be valid.
// default: false
func WithVerifyAll(all bool) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.All = all },
	}
}

// WithVerifyRsaPkcs1v15Sha256 adds signature verification using `rsa-v1_5-sha256` with the
// given public key using the given key id.
func WithVerifyRsaPkcs1v15Sha256(keyID string, pk *rsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.Keys[keyID] = &RsaPkcs1v15Sha256VerifyingKey{pk, keyID} },
	}
}

// WithVerifyRsaPssSha512 adds signature verification using `rsa-pss-sha512` with the
// given public key using the given key id.
func WithVerifyRsaPssSha512(keyID string, pk *rsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.Keys[keyID] = &RsaPssSha512VerifyingKey{pk, keyID} },
	}
}

// WithVerifyEcdsaP256Sha256 adds signature verification using `ecdsa-p256-sha256` with the
// given public key using the given key id.
func WithVerifyEcdsaP256Sha256(keyID string, pk *ecdsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.Keys[keyID] = &EcdsaP256VerifyingKey{pk, keyID} },
	}
}

// WithVerifyEcdsaP384Sha384 adds signature verification using `ecdsa-p384-sha384` with the
// given public key using the given key id.
func WithVerifyEcdsaP384Sha384(keyID string, pk *ecdsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.Keys[keyID] = &EcdsaP384VerifyingKey{pk, keyID} },
	}
}

// WithVerifyEd25519 adds signature verification using `ed25519` with the
// given public key using the given key id.
func WithVerifyEd25519(keyID string, pk ed25519.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.config.Keys[keyID] = &Ed25519VerifyingKey{pk, keyID} },
	}
}

// WithHmacSha256 adds signing or signature verification using `hmac-sha256` with the
// given shared secret using the given key id.
func WithHmacSha256(keyID string, secret []byte) signOrVerifyOption {
	return &optImpl{
		s: func(s *signer) { s.config.Key = &HmacSha256SigningKey{secret, keyID} },
		v: func(v *verifier) { v.config.Keys[keyID] = &HmacSha256VerifyingKey{secret, keyID} },
	}
}

// WithDigestAlgorithms sets the digest algorithms to use for signing or signature verification.
// default: sha-256
func WithDigestAlgorithms(algorithms ...DigestAlgorithm) digestOption {
	return &optImpl{
		d: func(d *digestor) { d.config.Algorithms = algorithms },
	}
}
