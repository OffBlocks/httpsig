package httpsig

import "net/http"

// NewVerifyMiddleware returns a configured http server middleware that can be used to wrap
// multiple handlers for http message signature and digest verification.
//
// Use the `WithVerify*` option funcs to configure signature verification algorithms that map
// to their provided key ids.
//
// Requests with missing signatures, malformed signature headers, expired signatures, or
// invalid signatures are rejected with a `400` response. Only one valid signature is required
// from the known key ids by default.
func NewVerifyMiddleware(opts ...verifyOption) func(http.Handler) http.Handler {
	// TODO: form and multipart support
	v := NewVerifier(opts...)

	serveErr := func(rw http.ResponseWriter) {
		// TODO: better error and custom error handler
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusBadRequest)

		_, _ = rw.Write([]byte("invalid required signature"))
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if err := v.Verify(MessageFromRequest(r)); err != nil {
				serveErr(rw)
				return
			}
			h.ServeHTTP(rw, r)
		})
	}
}
