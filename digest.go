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
