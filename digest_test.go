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
