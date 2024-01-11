// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dunglas/httpsfv"
)

// message is a minimal representation of an HTTP request or response, containing the values
// needed to construct a signature.
type Message struct {
	Method        string
	Authority     string
	URL           *url.URL
	Header        http.Header
	StatusCode    int
	RequestHeader *http.Header
	IsRequest     bool
	Context       context.Context
}

func MessageFromRequest(r *http.Request) *Message {
	return &Message{
		Method:    r.Method,
		Authority: r.Host,
		URL:       r.URL,
		Header:    r.Header.Clone(),
		IsRequest: true,
		Context:   r.Context(),
	}
}

func MessageFromResponse(r *http.Response) *Message {
	requestHeader := r.Request.Header.Clone()
	return &Message{
		Method:        r.Request.Method,
		Authority:     r.Request.Host,
		URL:           r.Request.URL,
		Header:        r.Header.Clone(),
		StatusCode:    r.StatusCode,
		RequestHeader: &requestHeader,
		IsRequest:     false,
		Context:       r.Request.Context(),
	}
}

func parseHeader(values []string) (httpsfv.StructuredFieldValue, error) {
	list, err := httpsfv.UnmarshalList(values)
	if err == nil {
		return list, nil
	}

	dict, err := httpsfv.UnmarshalDictionary(values)
	if err == nil {
		return dict, nil
	}

	item, err := httpsfv.UnmarshalItem(values)
	if err == nil {
		return item, nil
	}

	return nil, errors.New("unable to parse structured header")
}

func canonicaliseComponent(component string, params *httpsfv.Params, message *Message) (httpsfv.StructuredFieldValue, error) {
	_, isReq := params.Get("req")
	switch component {
	case "@method":
		// Section 2.2.1 covers canonicalisation of the method.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-method
		// Method should always be uppercase.
		if !message.IsRequest && !isReq {
			return nil, errors.New("method component not valid for responses")
		}
		return httpsfv.NewItem(strings.ToUpper(message.Method)), nil
	case "@target-uri":
		// Section 2.2.2 covers canonicalisation of the target-uri.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-target-uri
		if !message.IsRequest && !isReq {
			return nil, errors.New("target-uri component not valid for responses")
		}
		return httpsfv.NewItem(message.URL.String()), nil
	case "@authority":
		// Section 2.2.3 covers canonicalisation of the target-uri.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-authority
		if !message.IsRequest && !isReq {
			return nil, errors.New("authority component not valid for responses")
		}
		return httpsfv.NewItem(message.Authority), nil
	case "@scheme":
		// Section 2.2.4 covers canonicalisation of the scheme.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-scheme
		// Scheme should always be lowercase.
		if !message.IsRequest && !isReq {
			return nil, errors.New("scheme component not valid for responses")
		}
		return httpsfv.NewItem(strings.ToLower(message.URL.Scheme)), nil
	case "@request-target":
		// Section 2.2.5 covers canonicalisation of the request-target.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-request-target
		if !message.IsRequest && !isReq {
			return nil, errors.New("request-target component not valid for responses")
		}
		return httpsfv.NewItem(message.URL.RequestURI()), nil
	case "@path":
		// Section 2.2.6 covers canonicalisation of the path.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-path
		if !message.IsRequest && !isReq {
			return nil, errors.New("path component not valid for responses")
		}
		return httpsfv.NewItem(message.URL.Path), nil
	case "@query":
		// Section 2.2.7 covers canonicalisation of the query.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-query
		if !message.IsRequest && !isReq {
			return nil, errors.New("query component not valid for responses")
		}
		return httpsfv.NewItem("?" + message.URL.RawQuery), nil
	case "@query-param":
		// Section 2.2.8 covers canonicalisation of the query-param.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-query-parameters
		if !message.IsRequest && !isReq {
			return nil, errors.New("query-param component not valid for responses")
		}
		if params == nil {
			return nil, errors.New("query-param component requires a parameter")
		}
		name, ok := params.Get("name")
		if !ok {
			return nil, errors.New("query-param must have a named parameter")
		}
		if !message.URL.Query().Has(name.(string)) {
			return nil, fmt.Errorf("expected query parameter \"%s\" not found", name)
		}
		return httpsfv.NewItem(message.URL.Query().Get(name.(string))), nil
	case "@status":
		// Section 2.2.9 covers canonicalisation of the status.
		// https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html#name-status-code
		if message.IsRequest && isReq {
			return nil, errors.New("status component not valid for requests")
		}
		return httpsfv.NewItem(message.StatusCode), nil
	default:
		return nil, fmt.Errorf("unknown component: %s", component)
	}
}

func canonicaliseHeader(header string, params *httpsfv.Params, message *Message) (httpsfv.StructuredFieldValue, error) {
	var v []string
	if _, isReq := params.Get("req"); isReq {
		if message.IsRequest {
			return nil, errors.New("req parameter not valid for requests")
		}
		v = message.RequestHeader.Values(header)
	} else {
		v = message.Header.Values(header)
	}
	if len(v) == 0 {
		// empty values are permitted, but no values are not
		return nil, fmt.Errorf("header not found: %s", header)
	}

	_, isBs := params.Get("bs")
	_, isSf := params.Get("sf")
	key, isKey := params.Get("key")

	if isBs && (isSf || isKey) {
		return nil, errors.New("cannot have both `bs` and (implicit) `sf` parameters")
	}

	if isSf || isKey {
		// strict encoding of field
		parsed, err := parseHeader(v)
		if err != nil {
			return nil, err
		}

		if isKey {
			dict, ok := parsed.(*httpsfv.Dictionary)
			if !ok {
				return nil, errors.New("unable to parse header as dictionary")
			}

			if _, ok := key.(string); !ok {
				return nil, errors.New("key parameter must be a string")
			}

			val, ok := dict.Get(key.(string))
			if !ok {
				return nil, fmt.Errorf("unable to find key \"%s\" in structured field", key)
			}
			return val, nil
		}
		return parsed, nil
	}

	if isBs {
		encoded := httpsfv.List{}
		for _, sv := range v {
			decoded, err := base64.StdEncoding.DecodeString(sv)
			if err != nil {
				return nil, fmt.Errorf("unable to decode base64 value %s: %w", sv, err)
			}
			enc := base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(string(decoded))))
			item := httpsfv.NewItem([]byte(enc))
			encoded = append(encoded, item)
		}
		return encoded, nil
	}

	// raw encoding
	encoded := httpsfv.List{}
	for _, sv := range v {
		encoded = append(encoded, httpsfv.NewItem(strings.TrimSpace(sv)))
	}
	return encoded, nil
}

func quoteString(input string) string {
	// if it's not quoted, attempt to quote
	if !strings.HasPrefix(input, `"`) {
		// try to split the structured field
		name, rest := strings.Split(input, ";")[0], strings.Split(input, ";")[1:]
		// no params, just quote the whole thing
		if len(rest) == 0 {
			return fmt.Sprintf("\"%s\"", name)
		}
		// quote the first part and put the rest back as it was
		return fmt.Sprintf("\"%s\";%s", name, strings.Join(rest, ";"))
	}
	return input
}

func unquoteString(input string) string {
	// if it's quoted, attempt to unquote
	bytes := []byte(input)
	if len(bytes) > 2 && bytes[0] == '"' && bytes[len(bytes)-1] == '"' {
		bytes = bytes[1 : len(bytes)-1]
	}
	return string(bytes)
}

func formatSignatureBase(items []signatureItem) (string, error) {
	var b strings.Builder

	for _, item := range items {
		marshalledKey, err := httpsfv.Marshal(item.key)
		if err != nil {
			return "", err
		}

		marshalledValue, err := httpsfv.Marshal(item.value)
		if err != nil {
			return "", err
		}

		_, err = b.WriteString(fmt.Sprintf("%s: %s\n", marshalledKey, unquoteString(marshalledValue)))
		if err != nil {
			return "", err
		}
	}

	return strings.TrimSpace(b.String()), nil
}
