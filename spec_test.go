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
	"fmt"
	"net/http"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
)

func parseItem(s string) httpsfv.Item {
	i, err := httpsfv.UnmarshalItem([]string{s})
	if err != nil {
		panic(err)
	}
	return i
}

func TestCanonicaliseComponent_UnboundComponents(t *testing.T) {
	t.Run("derives @method component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		t.Run("uppercase", func(t *testing.T) {
			c, err := canonicaliseComponent("@method", httpsfv.NewParams(), MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"GET"}, c)
		})
		t.Run("lowercase", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Method = "get"

			c, err := canonicaliseComponent("@method", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"GET"}, c)
		})
	})
	t.Run("derives @target-uri component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		c, err := canonicaliseComponent("@target-uri", httpsfv.NewParams(), MessageFromRequest(req))
		assert.NoError(t, err)

		assert.Equal(t, []string{"https://example.com/foo?param=Value&Pet=dog"}, c)
	})
	t.Run("derives @authority component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		t.Run("with no port", func(t *testing.T) {
			c, err := canonicaliseComponent("@authority", httpsfv.NewParams(), MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
		t.Run("with port", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Host = "example.com:8080"

			c, err := canonicaliseComponent("@authority", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com:8080"}, c)
		})
		t.Run("with http default port", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL.Scheme = "http"
			r.Host = "example.com:80"

			c, err := canonicaliseComponent("@authority", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
		t.Run("with https default port", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL.Scheme = "https"
			r.Host = "example.com:443"

			c, err := canonicaliseComponent("@authority", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
		t.Run("uppercase", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Host = "EXAMPLE.COM"

			c, err := canonicaliseComponent("@authority", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
	})
	t.Run("derives @scheme component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		t.Run("uppercase", func(t *testing.T) {
			c, err := canonicaliseComponent("@scheme", httpsfv.NewParams(), MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"https"}, c)
		})
		t.Run("lowercase", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL.Scheme = "http"

			c, err := canonicaliseComponent("@scheme", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"http"}, c)
		})
	})
	t.Run("derives @request-target component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		c, err := canonicaliseComponent("@request-target", httpsfv.NewParams(), MessageFromRequest(req))
		assert.NoError(t, err)

		assert.Equal(t, []string{"/foo?param=Value&Pet=dog"}, c)
	})
	t.Run("derives @path component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		t.Run("simple", func(t *testing.T) {
			c, err := canonicaliseComponent("@path", httpsfv.NewParams(), MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/foo"}, c)
		})
		t.Run("with query", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo?param=Value&Pet=dog")

			c, err := canonicaliseComponent("@path", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/foo"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo%20bar")

			c, err := canonicaliseComponent("@path", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/foo%20bar"}, c)
		})
		t.Run("empty", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com")

			c, err := canonicaliseComponent("@path", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/"}, c)
		})
	})
	t.Run("derives @query component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}

		t.Run("simple", func(t *testing.T) {
			c, err := canonicaliseComponent("@query", httpsfv.NewParams(), MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"?param=Value&Pet=dog"}, c)
		})
		t.Run("empty", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo")

			c, err := canonicaliseComponent("@query", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"?"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo?param=Value%20bar&Pet=dog")

			c, err := canonicaliseComponent("@query", httpsfv.NewParams(), MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"?param=Value%20bar&Pet=dog"}, c)
		})
	})
	t.Run("derives @query-param component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header:        http.Header{},
			ContentLength: 18,
		}

		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "param")
			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"value"}, c)
		})
		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "foo")
			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"bar"}, c)
		})
		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "baz")
			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{"batman"}, c)
		})
		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "qux")
			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(req))
			assert.NoError(t, err)

			assert.Equal(t, []string{""}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "var")
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")

			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"this%20is%20a%20big%0Amultiline%20value"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "bar")
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")

			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"with%20plus%20whitespace"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("name", "fa%C3%A7ade%22%3A%20")
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")

			c, err := canonicaliseComponent("@query-param", params, MessageFromRequest(r))
			assert.NoError(t, err)

			assert.Equal(t, []string{"something"}, c)
		})
	})
	t.Run("derives @status component", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request: &http.Request{
				Header: http.Header{},
			},
		}

		c, err := canonicaliseComponent("@status", httpsfv.NewParams(), MessageFromResponse(resp))
		assert.NoError(t, err)

		assert.Equal(t, []string{"200"}, c)
	})
}

func TestCanonicaliseComponent_Request_Response_BoundComponents(t *testing.T) {
	t.Run("derives @method component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		t.Run("uppercase", func(t *testing.T) {
			c, err := canonicaliseComponent("@method", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"GET"}, c)
		})
		t.Run("lowercase", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Method = "get"

			c, err := canonicaliseComponent("@method", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"GET"}, c)
		})
	})
	t.Run("derives @target-uri component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		c, err := canonicaliseComponent("@target-uri", params, MessageFromResponse(resp))
		assert.NoError(t, err)

		assert.Equal(t, []string{"https://example.com/foo?param=Value&Pet=dog"}, c)
	})
	t.Run("derives @authority component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		t.Run("with no port", func(t *testing.T) {
			c, err := canonicaliseComponent("@authority", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
		t.Run("with port", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Host = "example.com:8080"
			resp.Request = r

			c, err := canonicaliseComponent("@authority", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com:8080"}, c)
		})
		t.Run("with http default port", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL.Scheme = "http"
			r.Host = "example.com:80"
			resp.Request = r

			c, err := canonicaliseComponent("@authority", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
		t.Run("with https default port", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL.Scheme = "https"
			r.Host = "example.com:443"
			resp.Request = r

			c, err := canonicaliseComponent("@authority", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
		t.Run("uppercase", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.Host = "EXAMPLE.COM"
			resp.Request = r

			c, err := canonicaliseComponent("@authority", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"example.com"}, c)
		})
	})
	t.Run("derives @scheme component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		t.Run("uppercase", func(t *testing.T) {
			c, err := canonicaliseComponent("@scheme", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"https"}, c)
		})
		t.Run("lowercase", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL.Scheme = "http"
			resp.Request = r

			c, err := canonicaliseComponent("@scheme", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"http"}, c)
		})
	})
	t.Run("derives @request-target component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		c, err := canonicaliseComponent("@request-target", params, MessageFromResponse(resp))
		assert.NoError(t, err)

		assert.Equal(t, []string{"/foo?param=Value&Pet=dog"}, c)
	})
	t.Run("derives @path component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		t.Run("simple", func(t *testing.T) {
			c, err := canonicaliseComponent("@path", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/foo"}, c)
		})
		t.Run("with query", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo?param=Value&Pet=dog")
			resp.Request = r

			c, err := canonicaliseComponent("@path", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/foo"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo%20bar")
			resp.Request = r

			c, err := canonicaliseComponent("@path", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/foo%20bar"}, c)
		})
		t.Run("empty", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com")
			resp.Request = r

			c, err := canonicaliseComponent("@path", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"/"}, c)
		})
	})
	t.Run("derives @query component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/foo?param=Value&Pet=dog"),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}
		params := httpsfv.NewParams()
		params.Add("req", true)
		resp.Request = req

		t.Run("simple", func(t *testing.T) {
			c, err := canonicaliseComponent("@query", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"?param=Value&Pet=dog"}, c)
		})
		t.Run("empty", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo")
			resp.Request = r

			c, err := canonicaliseComponent("@query", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"?"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/foo?param=Value%20bar&Pet=dog")
			resp.Request = r

			c, err := canonicaliseComponent("@query", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"?param=Value%20bar&Pet=dog"}, c)
		})
	})
	t.Run("derives @query-param component", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header:        http.Header{},
			ContentLength: 18,
		}
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request:       req,
		}

		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "param")
			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"value"}, c)
		})
		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "foo")
			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"bar"}, c)
		})
		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "baz")
			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"batman"}, c)
		})
		t.Run("simple", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "qux")
			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{""}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "var")
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
			resp.Request = r

			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"this%20is%20a%20big%0Amultiline%20value"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "bar")
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")

			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"with%20plus%20whitespace"}, c)
		})
		t.Run("with encoded values", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("name", "fa%C3%A7ade%22%3A%20")
			r := req.Clone(req.Context())
			r.URL = parse("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")

			c, err := canonicaliseComponent("@query-param", params, MessageFromResponse(resp))
			assert.NoError(t, err)

			assert.Equal(t, []string{"something"}, c)
		})
	})
}

func TestCanonicaliseComponent_ErrorConditions(t *testing.T) {
	for _, tc := range []struct {
		component string
		response  http.Response
	}{
		{
			"@method",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@target-uri",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@authority",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@scheme",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@request-target",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@path",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@query",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		{
			"@query-param",
			http.Response{
				StatusCode:    200,
				Header:        http.Header{},
				ContentLength: 18,
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("error for %s on response", tc.component), func(t *testing.T) {
			_, err := canonicaliseComponent(tc.component, httpsfv.NewParams(), MessageFromResponse(&tc.response))
			assert.Error(t, err)
		})
	}
	t.Run("error for missing @query-param name", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header:        http.Header{},
			ContentLength: 18,
		}
		_, err := canonicaliseComponent("@query-param", httpsfv.NewParams(), MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error for missing @query-param", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header:        http.Header{},
			ContentLength: 18,
		}
		params := httpsfv.NewParams()
		params.Add("name", "missing")
		_, err := canonicaliseComponent("@query-param", params, MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error for @status on request", func(t *testing.T) {
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header:        http.Header{},
			ContentLength: 18,
		}
		_, err := canonicaliseComponent("@status", httpsfv.NewParams(), MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error for @status on response request", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:    200,
			Header:        http.Header{},
			ContentLength: 18,
			Request: &http.Request{
				Header: http.Header{},
			},
		}
		params := httpsfv.NewParams()
		params.Add("req", true)

		_, err := canonicaliseComponent("@status", params, MessageFromResponse(resp))
		assert.Error(t, err)
	})
}

func TestCanonocaliseHeaders(t *testing.T) {
	t.Run("general header extraction", func(t *testing.T) {
		// headers are always in a canonical form
		headers := http.Header{
			"Testheader":    []string{"test"},
			"Test-Header-1": []string{"test1"},
			"Test-Header-2": []string{"test2"},
			"Test-Header-3": []string{"test3"},
			"Test-Header-4": []string{"test4"},
		}
		req := &http.Request{
			Method:        "GET",
			Host:          "example.com",
			URL:           parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header:        headers,
			ContentLength: 18,
		}

		for key, value := range map[string]string{
			"testheader":    "test",
			"test-header-1": "test1",
			"Test-Header-2": "test2",
			"test-Header-3": "test3",
			"TEST-HEADER-4": "test4",
		} {
			t.Run(fmt.Sprintf("extracts %s", key), func(t *testing.T) {
				c, err := canonicaliseHeader(key, httpsfv.NewParams(), MessageFromRequest(req))
				assert.NoError(t, err)
				assert.Equal(t, []string{value}, c)
			})
		}
		t.Run("error on missing header", func(t *testing.T) {
			_, err := canonicaliseHeader("missing", httpsfv.NewParams(), MessageFromRequest(req))
			assert.Error(t, err)
		})
	})
	t.Run("raw headers", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":              []string{"www.example.com"},
				"Date":              []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
				"X-Ows-Header":      []string{"  Leading and trailing whitespace.  "},
				"X-Obs-Fold-Header": []string{"Obsolete\n    line folding."},
				"Cache-Control":     []string{"max-age=60", "   must-revalidate"},
				"Example-Dict":      []string{" a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
				"X-Empty-Header":    []string{""},
			},
			ContentLength: 18,
		}

		for key, value := range map[string][]string{
			"host":              {"www.example.com"},
			"date":              {"Tue, 20 Apr 2021 02:07:56 GMT"},
			"x-ows-header":      {"Leading and trailing whitespace."},
			"x-obs-fold-header": {"Obsolete line folding."},
			"cache-control":     {"max-age=60", "must-revalidate"},
			"example-dict":      {"a=1, b=2;x=1;y=2, c=(a b c)"},
			"x-empty-header":    {""},
		} {
			t.Run(fmt.Sprintf("extracts %s", key), func(t *testing.T) {
				c, err := canonicaliseHeader(key, httpsfv.NewParams(), MessageFromRequest(req))
				assert.NoError(t, err)
				assert.Equal(t, value, c)
			})
		}
		t.Run("error on missing header", func(t *testing.T) {
			_, err := canonicaliseHeader("missing", httpsfv.NewParams(), MessageFromRequest(req))
			assert.Error(t, err)
		})
	})
	t.Run("sf header extraction", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":              []string{"www.example.com"},
				"Date":              []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
				"X-Ows-Header":      []string{"  Leading and trailing whitespace.  "},
				"X-Obs-Fold-Header": []string{"Obsolete\n    line folding."},
				"Cache-Control":     []string{"max-age=60", "   must-revalidate"},
				"Example-Dict":      []string{" a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
				"X-Empty-Header":    []string{""},
			},
			ContentLength: 18,
		}
		t.Run("extracts example-dict", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("sf", true)
			c, err := canonicaliseHeader("example-dict", httpsfv.NewParams(), MessageFromRequest(req))
			assert.NoError(t, err)
			assert.Equal(t, []string{"a=1, b=2;x=1;y=2, c=(a b c)"}, c)
		})
	})
	t.Run("key from structured header", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":         []string{"www.example.com"},
				"Example-Dict": []string{" a=1, b=2;x=1;y=2, c=(a   b    c), d"},
			},
			ContentLength: 18,
		}
		t.Run("extract integer key", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("key", "a")
			c, err := canonicaliseHeader("example-dict", params, MessageFromRequest(req))
			assert.NoError(t, err)
			assert.Equal(t, []string{"1"}, c)
		})
		t.Run("extract boolean key", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("key", "d")
			c, err := canonicaliseHeader("example-dict", params, MessageFromRequest(req))
			assert.NoError(t, err)
			assert.Equal(t, []string{"?1"}, c)
		})
		t.Run("extract parameters", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("key", "b")
			c, err := canonicaliseHeader("example-dict", params, MessageFromRequest(req))
			assert.NoError(t, err)
			assert.Equal(t, []string{"2;x=1;y=2"}, c)
		})
		t.Run("extract inner list", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("key", "c")
			c, err := canonicaliseHeader("example-dict", params, MessageFromRequest(req))
			assert.NoError(t, err)
			assert.Equal(t, []string{"(a b c)"}, c)
		})
	})
	t.Run("bs from structured header", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":           []string{"www.example.com"},
				"Example-Header": []string{"value, with, lots", "of, commas"},
			},
			ContentLength: 18,
		}
		t.Run("encodes multiple headers separately", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("bs", true)
			c, err := canonicaliseHeader("example-header", params, MessageFromRequest(req))
			assert.NoError(t, err)
			assert.Equal(t, []string{":dmFsdWUsIHdpdGgsIGxvdHM=:", ":b2YsIGNvbW1hcw==:"}, c)
		})
		t.Run("encodes single header", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("bs", true)
			r := req.Clone(req.Context())
			r.Header.Set("Example-Header", "value, with, lots, of, commas")

			c, err := canonicaliseHeader("example-header", params, MessageFromRequest(r))
			assert.NoError(t, err)
			assert.Equal(t, []string{":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"}, c)
		})
	})
	t.Run("request-response bound header", func(t *testing.T) {
		/*

		   const response: Response = {
		       status: 503,
		       headers: {
		           'Date': 'Tue, 20 Apr 2021 02:07:56 GMT',
		           'Content-Type': 'application/json',
		           'Content-Length': '62',
		       },
		   };
		*/
		req := &http.Request{
			Method: "POST",
			Host:   "example.com",
			URL:    parse("https://example.com/foo?param=Value&Pet=dog"),
			Header: http.Header{
				"Host":            []string{"www.example.com"},
				"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
				"Content-Type":    []string{"application/json"},
				"Content-Digest":  []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
				"Content-Length":  []string{"18"},
				"Signature-Input": []string{"sig1=('@method' '@authority' '@path' 'content-digest' 'content-length' 'content-type');created=1618884475;keyid='test-key-rsa-pss'"},
				"Signature":       []string{"sig1=:LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziCLuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY/UkBIS1M8Brc8IODsn5DFIrG0IrburbLi0uCc+E2ZIIb6HbUJ+o+jP58JelMTe0QE3IpWINTEzpxjqDf5/Df+InHCAkQCTuKsamjWXUpyOT1Wkxi7YPVNOjW4MfNuTZ9HdbD2Tr65+BXeTG9ZS/9SWuXAc+BZ8WyPz0QRz//ec3uWXd7bYYODSjRAxHqX+S1ag3LZElYyUKaAIjZ8MGOt4gXEwCSLDv/zqxZeWLj/PDkn6w==:"},
			},
		}
		resp := &http.Response{
			StatusCode: 503,
			Header: http.Header{
				"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
				"Content-Type":   []string{"application/json"},
				"Content-Length": []string{"62"},
			},
			Request: req,
		}
		t.Run("binds requests and responses", func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("req", true)
			params.Add("key", "sig1")

			c, err := canonicaliseHeader("signature", params, MessageFromResponse(resp))
			assert.NoError(t, err)
			assert.Equal(t, []string{":LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziCLuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY/UkBIS1M8Brc8IODsn5DFIrG0IrburbLi0uCc+E2ZIIb6HbUJ+o+jP58JelMTe0QE3IpWINTEzpxjqDf5/Df+InHCAkQCTuKsamjWXUpyOT1Wkxi7YPVNOjW4MfNuTZ9HdbD2Tr65+BXeTG9ZS/9SWuXAc+BZ8WyPz0QRz//ec3uWXd7bYYODSjRAxHqX+S1ag3LZElYyUKaAIjZ8MGOt4gXEwCSLDv/zqxZeWLj/PDkn6w==:"}, c)
		})
	})
}

func TestCanonocaliseHeaders_ErrorConditions(t *testing.T) {
	t.Run("error if both bs/sf params provided", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":         []string{"www.example.com"},
				"Structured":   []string{"test=123"},
				"Content-Type": []string{"application/json"},
			},
		}
		params := httpsfv.NewParams()
		params.Add("sf", true)
		params.Add("bs", true)

		_, err := canonicaliseHeader("structured", params, MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error if both bs and implicit sf params provided", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":         []string{"www.example.com"},
				"Structured":   []string{"test=123"},
				"Content-Type": []string{"application/json"},
			},
		}
		params := httpsfv.NewParams()
		params.Add("bs", true)
		params.Add("key", "val")

		_, err := canonicaliseHeader("structured", params, MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error if sf params provided for non structured field", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":         []string{"www.example.com"},
				"Date":         []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
				"Structured":   []string{"test=123"},
				"Content-Type": []string{"application/json"},
			},
		}
		params := httpsfv.NewParams()
		params.Add("sf", true)
		params.Add("key", "val")

		_, err := canonicaliseHeader("date", params, MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error if sf params provided for non dictionary", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":         []string{"www.example.com"},
				"Notadict":     []string{"(a b c)"},
				"Content-Type": []string{"application/json"},
			},
		}
		params := httpsfv.NewParams()
		params.Add("sf", true)
		params.Add("key", "val")

		_, err := canonicaliseHeader("notadict", params, MessageFromRequest(req))
		assert.Error(t, err)
	})
	t.Run("error if key is missing for structured field", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			Host:   "example.com",
			URL:    parse("https://example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host":         []string{"www.example.com"},
				"Structured":   []string{"test=123"},
				"Content-Type": []string{"application/json"},
			},
		}
		params := httpsfv.NewParams()
		params.Add("key", "val")

		_, err := canonicaliseHeader("structured", params, MessageFromRequest(req))
		assert.Error(t, err)
	})
}

func TestCreateSignatureBase_Headers(t *testing.T) {
	t.Run("header fields", func(t *testing.T) {
		req := &http.Request{
			Method: "POST",
			URL:    parse("https://www.example.com/"),
			Header: http.Header{
				"Host":                  []string{"www.example.com"},
				"Date":                  []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
				"X-Ows-Header":          []string{"  Leading and trailing whitespace.  "},
				"X-Obs-Fold-Header":     []string{"Obsolete\n    line folding."},
				"Cache-Control":         []string{"max-age=60", "   must-revalidate"},
				"Example-Dict":          []string{" a=1,    b=2;x=1;y=2,   c=(a   b   c), d"},
				"Example-Header":        []string{"value, with, lots", "of, commas"},
				"Example-Header-Single": []string{"value, with, lots, of, commas"},
				"X-Empty-Header":        []string{""},
			},
		}
		for _, tc := range []struct {
			name   string
			fields []string
			expect []signatureItem
		}{
			{
				"creates a signature base from raw headers",
				[]string{
					"host",
					"date",
					"x-ows-header",
					"x-obs-fold-header",
					"cache-control",
					"example-dict",
				},
				[]signatureItem{
					{httpsfv.NewItem("host"), []string{"www.example.com"}},
					{httpsfv.NewItem("date"), []string{"Tue, 20 Apr 2021 02:07:56 GMT"}},
					{httpsfv.NewItem("x-ows-header"), []string{"Leading and trailing whitespace."}},
					{httpsfv.NewItem("x-obs-fold-header"), []string{"Obsolete line folding."}},
					{httpsfv.NewItem("cache-control"), []string{"max-age=60", "must-revalidate"}},
					{httpsfv.NewItem("example-dict"), []string{"a=1, b=2;x=1;y=2, c=(a b c), d"}},
				},
			},
			{
				"extracts an empty header",
				[]string{
					"x-empty-header",
				},
				[]signatureItem{
					{httpsfv.NewItem("x-empty-header"), []string{""}},
				},
			},
			{
				"extracts strict formatted headers",
				[]string{
					"example-dict;sf",
				},
				[]signatureItem{
					{parseItem(`"example-dict";sf`), []string{"a=1, b=2;x=1;y=2, c=(a b c), d"}},
				},
			},
			{
				"extracts keys from dictionary headers",
				[]string{
					`example-dict;key="a"`,
					`example-dict;key="d"`,
					`example-dict;key="b"`,
					`example-dict;key="c"`,
				},
				[]signatureItem{
					{parseItem(`"example-dict";key="a"`), []string{"1"}},
					{parseItem(`"example-dict";key="d"`), []string{"?1"}},
					{parseItem(`"example-dict";key="b"`), []string{"2;x=1;y=2"}},
					{parseItem(`"example-dict";key="c"`), []string{"(a b c)"}},
				},
			},
			{
				"extracts binary formatted headers split",
				[]string{
					"example-header;bs",
				},
				[]signatureItem{
					{parseItem(`"example-header";bs`), []string{":dmFsdWUsIHdpdGgsIGxvdHM=:", ":b2YsIGNvbW1hcw==:"}},
				},
			},
			{
				"extracts binary formatted headers single",
				[]string{
					"example-header-single;bs",
				},
				[]signatureItem{
					{parseItem(`"example-header-single";bs`), []string{":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"}},
				},
			},
			{
				"ignores @signature-params component",
				[]string{
					"host",
					"date",
					"x-ows-header",
					"x-obs-fold-header",
					"cache-control",
					"example-dict",
					"@signature-params",
				},
				[]signatureItem{
					{httpsfv.NewItem("host"), []string{"www.example.com"}},
					{httpsfv.NewItem("date"), []string{"Tue, 20 Apr 2021 02:07:56 GMT"}},
					{httpsfv.NewItem("x-ows-header"), []string{"Leading and trailing whitespace."}},
					{httpsfv.NewItem("x-obs-fold-header"), []string{"Obsolete line folding."}},
					{httpsfv.NewItem("cache-control"), []string{"max-age=60", "must-revalidate"}},
					{httpsfv.NewItem("example-dict"), []string{"a=1, b=2;x=1;y=2, c=(a b c), d"}},
				},
			},
			{
				"ignores @signature-params component with arbitrary params",
				[]string{
					"host",
					"date",
					"x-ows-header",
					"x-obs-fold-header",
					"cache-control",
					"example-dict",
					`@signature-params;test=:AAA=:;test2=test`,
				},
				[]signatureItem{
					{httpsfv.NewItem("host"), []string{"www.example.com"}},
					{httpsfv.NewItem("date"), []string{"Tue, 20 Apr 2021 02:07:56 GMT"}},
					{httpsfv.NewItem("x-ows-header"), []string{"Leading and trailing whitespace."}},
					{httpsfv.NewItem("x-obs-fold-header"), []string{"Obsolete line folding."}},
					{httpsfv.NewItem("cache-control"), []string{"max-age=60", "must-revalidate"}},
					{httpsfv.NewItem("example-dict"), []string{"a=1, b=2;x=1;y=2, c=(a b c), d"}},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, err := createSignatureBase(tc.fields, MessageFromRequest(req))
				assert.NoError(t, err)
				assert.Equal(t, tc.expect, c)
			})
		}
	})
}

func TestCreateSignatureBase_DerivedComponents(t *testing.T) {
	t.Run("derived components", func(t *testing.T) {
		req := &http.Request{
			Method: "POST",
			Host:   "www.example.com",
			URL:    parse("https://www.example.com/path?param=value&foo=bar&baz=batman&qux="),
			Header: http.Header{
				"Host": []string{"www.example.com"},
			},
		}
		for _, tc := range []struct {
			name   string
			fields []string
			expect []signatureItem
		}{
			{
				"derives @method",
				[]string{
					"@method",
				},
				[]signatureItem{
					{httpsfv.NewItem("@method"), []string{"POST"}},
				},
			},
			{
				"derives @target-uri",
				[]string{
					"@target-uri",
				},
				[]signatureItem{
					{httpsfv.NewItem("@target-uri"), []string{"https://www.example.com/path?param=value&foo=bar&baz=batman&qux="}},
				},
			},
			{
				"derives @authority",
				[]string{
					"@authority",
				},
				[]signatureItem{
					{httpsfv.NewItem("@authority"), []string{"www.example.com"}},
				},
			},
			{
				"derives @scheme",
				[]string{
					"@scheme",
				},
				[]signatureItem{
					{httpsfv.NewItem("@scheme"), []string{"https"}},
				},
			},
			{
				"derives @request-target",
				[]string{
					"@request-target",
				},
				[]signatureItem{
					{httpsfv.NewItem("@request-target"), []string{"/path?param=value&foo=bar&baz=batman&qux="}},
				},
			},
			{
				"derives @path",
				[]string{
					"@path",
				},
				[]signatureItem{
					{httpsfv.NewItem("@path"), []string{"/path"}},
				},
			},
			{
				"derives @query",
				[]string{
					"@query",
				},
				[]signatureItem{
					{httpsfv.NewItem("@query"), []string{"?param=value&foo=bar&baz=batman&qux="}},
				},
			},
			{
				"derives @query-param",
				[]string{
					`@query-param;name="baz"`, // name is required
				},
				[]signatureItem{
					{parseItem(`"@query-param";name="baz"`), []string{"batman"}},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, err := createSignatureBase(tc.fields, MessageFromRequest(req))
				assert.NoError(t, err)
				assert.Equal(t, tc.expect, c)
			})
		}
	})
	t.Run("derives @status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Request: &http.Request{
				Header: http.Header{},
			},
		}
		c, err := createSignatureBase([]string{"@status"}, MessageFromResponse(resp))
		assert.NoError(t, err)
		assert.Equal(t, []signatureItem{
			{httpsfv.NewItem("@status"), []string{"200"}},
		}, c)
	})
}

func TestCreateSignatureBase_FullExample(t *testing.T) {
	req := &http.Request{
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
	}
	t.Run("produces a signature base for a request", func(t *testing.T) {
		c, err := createSignatureBase([]string{
			"@method",
			"@authority",
			"@path",
			"content-digest",
			"content-length",
			"content-type",
		}, MessageFromRequest(req))
		assert.NoError(t, err)
		assert.Equal(t, []signatureItem{
			{httpsfv.NewItem("@method"), []string{"POST"}},
			{httpsfv.NewItem("@authority"), []string{"example.com"}},
			{httpsfv.NewItem("@path"), []string{"/foo"}},
			{httpsfv.NewItem("content-digest"), []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"}},
			{httpsfv.NewItem("content-length"), []string{"18"}},
			{httpsfv.NewItem("content-type"), []string{"application/json"}},
		}, c)
	})
}

func TestFormatSignatureBase(t *testing.T) {
	t.Run("formats @method", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@method"), []string{"POST"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@method": POST`, f)
	})
	t.Run("derives @target-uri", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@target-uri"), []string{"https://www.example.com/path?param=value"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@target-uri": https://www.example.com/path?param=value`, f)
	})
	t.Run("derives @authority", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@authority"), []string{"www.example.com"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@authority": www.example.com`, f)
	})
	t.Run("derives @scheme", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@scheme"), []string{"https"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@scheme": https`, f)
	})
	t.Run("derives @request-target", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@request-target"), []string{"/path?param=value"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@request-target": /path?param=value`, f)
	})
	t.Run("derives @path", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@path"), []string{"/path"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@path": /path`, f)
	})
	t.Run("derives @query", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@query"), []string{"?param=value&foo=bar&baz=batman"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@query": ?param=value&foo=bar&baz=batman`, f)
		c = []signatureItem{
			{httpsfv.NewItem("@query"), []string{"?queryString"}},
		}
		f, err = formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@query": ?queryString`, f)
		c = []signatureItem{
			{httpsfv.NewItem("@query"), []string{"?"}},
		}
		f, err = formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@query": ?`, f)
	})
	t.Run("derives @query-param", func(t *testing.T) {
		c := []signatureItem{
			{parseItem(`"@query-param";name="baz"`), []string{"batman"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@query-param";name="baz": batman`, f)
		c = []signatureItem{
			{parseItem(`"@query-param";name="qux"`), []string{""}},
		}
		f, err = formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@query-param";name="qux": `, f)
		c = []signatureItem{
			{parseItem(`"@query-param";name="param"`), []string{"value"}},
		}
		f, err = formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@query-param";name="param": value`, f)
	})
	t.Run("derives @status", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("@status"), []string{"200"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"@status": 200`, f)
	})
	t.Run("formats many headers", func(t *testing.T) {
		c := []signatureItem{
			{httpsfv.NewItem("host"), []string{"www.example.com"}},
			{httpsfv.NewItem("date"), []string{"Tue, 20 Apr 2021 02:07:56 GMT"}},
			{httpsfv.NewItem("x-ows-header"), []string{"Leading and trailing whitespace."}},
			{httpsfv.NewItem("x-obs-fold-header"), []string{"Obsolete line folding."}},
			{httpsfv.NewItem("cache-control"), []string{"max-age=60", "must-revalidate"}},
			{httpsfv.NewItem("example-dict"), []string{"a=1,    b=2;x=1;y=2,   c=(a   b   c)"}},
			{httpsfv.NewItem("x-empty-header"), []string{""}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"host": www.example.com`+"\n"+`"date": Tue, 20 Apr 2021 02:07:56 GMT`+"\n"+`"x-ows-header": Leading and trailing whitespace.`+"\n"+`"x-obs-fold-header": Obsolete line folding.`+"\n"+`"cache-control": max-age=60, must-revalidate`+"\n"+`"example-dict": a=1,    b=2;x=1;y=2,   c=(a   b   c)`+"\n"+`"x-empty-header": `, f)
	})
	t.Run("formats strict formatted headers", func(t *testing.T) {
		c := []signatureItem{
			{parseItem(`"example-dict";sf`), []string{"a=1, b=2;x=1;y=2, c=(a b c)"}},
		}
		f, err := formatSignatureBase(c)
		assert.NoError(t, err)
		assert.Equal(t, `"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)`, f)
	})
}
