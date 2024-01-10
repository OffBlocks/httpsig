package httpsig

import "net/http"

// NewSignTransport returns a new client transport that wraps the provided transport with
// http message signing and body digest creation.
//
// Use the various `WithSign*` option funcs to configure signature algorithms with their provided
// key ids. You must provide at least one signing option. A signature for every provided key id is
// included on each request. Multiple included signatures allow you to gracefully introduce stronger
// algorithms, rotate keys, etc.
func NewSignTransport(transport http.RoundTripper, opts ...signOption) http.RoundTripper {
	s := NewSigner(opts...)

	return rt(func(r *http.Request) (*http.Response, error) {
		hdr, err := s.Sign(MessageFromRequest(r))
		if err != nil {
			return nil, err
		}
		r.Header = hdr
		return transport.RoundTrip(r)
	})
}

type rt func(*http.Request) (*http.Response, error)

func (r rt) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }
