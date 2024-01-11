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

const (
	SignatureHeader      = "Signature"
	SignatureInputHeader = "Signature-Input"
	ContentDigestHeader  = "Content-Digest"
)

// Algorithm is the signature algorithm to use. Available algorithms are:
// - RSASSA-PKCS1-v1_5 using SHA-256 (rsa-v1_5-sha256)
// - RSASSA-PSS using SHA-512 (rsa-pss-sha512)
// - ECDSA using curve P-256 DSS and SHA-256 (ecdsa-p256-sha256)
// - ECDSA using curve P-384 DSS and SHA-384 (ecdsa-p384-sha384)
// - EdDSA using curve edwards25519 (ed25519)
// - HMAC using SHA-256 (hmac-sha256)
type Algorithm string

const (
	AlgorithmRsaPkcs1v15Sha256 Algorithm = "rsa-v1_5-sha256"
	AlgorithmRsaPssSha512      Algorithm = "rsa-pss-sha512"
	AlgorithmEcdsaP256Sha256   Algorithm = "ecdsa-p256-sha256"
	AlgorithmEcdsaP384Sha384   Algorithm = "ecdsa-p384-sha384"
	AlgorithmEd25519           Algorithm = "ed25519"
	AlgorithmHmacSha256        Algorithm = "hmac-sha256"
)

// DigestAlgorithm is the digest algorithm to use. Available algorithms are:
// - SHA-256 (sha-256)
// - SHA-512 (sha-512)
type DigestAlgorithm string

const (
	DigestAlgorithmSha256 DigestAlgorithm = "sha-256"
	DigestAlgorithmSha512 DigestAlgorithm = "sha-512"
)
