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
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"net/http"

	"github.com/dunglas/httpsfv"
)

type DigestConfig struct {
	// List of digest algorithms to use when creating a digest header.
	// default: sha-256
	Algorithms []DigestAlgorithm
}

type Digestor struct {
	*digestor
}

// NewDigestor creates a new digestor with the given options
func NewDigestor(opts ...digestOption) *Digestor {
	d := digestor{}

	for _, o := range opts {
		o.configureDigest(&d)
	}

	if len(d.config.Algorithms) == 0 {
		d.config.Algorithms = []DigestAlgorithm{DigestAlgorithmSha256}
	}

	return &Digestor{&d}
}

// Digest creates a digest header for the given body
func (d *Digestor) Digest(body []byte) (http.Header, error) {
	return d.digestor.Digest(body)
}

type digestor struct {
	config DigestConfig
}

func (d *digestor) Digest(body []byte) (http.Header, error) {
	dict := httpsfv.NewDictionary()

	for _, algorithm := range d.config.Algorithms {
		digest, err := calculateDigest(body, algorithm)
		if err != nil {
			return nil, err
		}

		dict.Add(string(algorithm), httpsfv.NewItem(digest))
	}

	marshalled, err := httpsfv.Marshal(dict)
	if err != nil {
		return nil, err
	}

	hdr := make(http.Header)
	hdr.Set(ContentDigestHeader, marshalled)

	return hdr, nil
}

func calculateDigest(body []byte, algorithm DigestAlgorithm) ([]byte, error) {
	switch algorithm {
	case DigestAlgorithmSha256:
		digest := sha256.Sum256(body)
		return digest[:], nil
	case DigestAlgorithmSha512:
		digest := sha512.Sum512(body)
		return digest[:], nil
	}

	return nil, errors.New("unsupported digest algorithm")
}
