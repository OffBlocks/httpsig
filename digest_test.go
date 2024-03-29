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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigest_SHA512(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	assert.Equal(t, `sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:`, hdr.Get(ContentDigestHeader))
}

func TestDigest_SHA256(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	assert.Equal(t, `sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:`, hdr.Get(ContentDigestHeader))
}

func TestVerify_SHA256(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)
}

func TestVerify_SHA512(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)
}

func TestDigest_SHA256_Verify_SHA256_SHA512(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)

	d = NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)
}

func TestDigest_SHA256_SHA512_Verify_SHA256_SHA512(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)

	d = NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)
}

func TestDigest_SHA256_SHA512_Verify_SHA256(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)

	d = NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
	)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)
}

func TestDigest_SHA256_SHA512_Verify_SHA512(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")

	d := NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha256),
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	hdr, err := d.Digest(body)
	assert.NoError(t, err)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)

	d = NewDigestor(
		WithDigestAlgorithms(DigestAlgorithmSha512),
	)

	err = d.Verify(body, hdr)
	assert.NoError(t, err)
}
