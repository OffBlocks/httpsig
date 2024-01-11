<!--
  Attractive html formatting for rendering in github. sorry text editor
  readers! Besides the header and section links, everything should be clean and
  readable.
-->
<h1 align="center">httpsig</h1>
<p align="center"><i>Standards-based HTTP request signing and verification for <a href="https://golang.org">Go</a></i></p>

<div align="center">
  <a href="https://pkg.go.dev/github.com/offblocks/httpsig"><img src="https://pkg.go.dev/badge/github.com/offblocks/httpsig.svg" alt="Go Reference"></a>
  <img alt="Alpha Quality" src="https://img.shields.io/badge/status-ALPHA-orange.svg" >
  <a href="https://github.com/offblocks/httpsig/actions/workflows/go.yml"><img alt="Build Status" src="https://github.com/offblocks/httpsig/actions/workflows/go.yml/badge.svg?branch=main"></a>
  <a href="./LICENSE"><img alt="BSD license" src="https://img.shields.io/badge/license-BSD-blue.svg"></a>
  <a href="https://codecov.io/gh/offblocks/httpsig"><img alt="codecov" src="https://img.shields.io/codecov/c/github/offblocks/httpsig.svg"></a>
  <a href="https://goreportcard.com/report/github.com/offblocks/httpsig"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/offblocks/httpsig"></a>
</div><br /><br />

## Introduction

`httpsig` provides support for signing and verifying HTTP requests according
to the [HTTP Message Signatures][msgsig] draft standard. This standard focuses
on signing headers and request paths, and you probably want to sign the
request body too, so body digest calculation according to
[Digest Headers][dighdr] is included.

Signed HTTP requests are ideal for scenarios like sending webhooks, allowing
recievers to securely verify the request came from your server, mitigate replay
attacks, etc.

Contrary to the commonly-used `x-hub-signature`, The standards implemented by
this package provide a signature of the entire request, including HTTP headers
and the request path.

## Usage

### Standalone Signing and Verification

To sign a request, first instantiate a `Signer` using your preferred key and signing algorithm:

```go
// Create a signer
signer := httpsig.NewSigner(httpsig.WithSignEcdsaP256Sha256("key1", privKey))

// Create a request
req, _ := http.NewRequest("GET", "https://some-url.com", nil)

// Sign the request
header, _ := signer.Sign(httpsig.MessageFromRequest(req))

// Add the signature to the request
req.Header = header
```

To verify a response, instantiate a `Verifier` using your preferred key and signing algorithm:

```go
// Receive a response from server
resp, _ := client.Post("https://some-url.com", "application/json", &buf)

// Create a verifier
verifier := httpsig.NewVerifier(httpsig.WithVerifyEcdsaP256Sha256("key1", pubKey))

// Verify the response
err := verifier.Verify(httpsig.MessageFromResponse(resp))
```

### Signing HTTP Requests in Clients

To sign HTTP requests from a client, wrap an `http.Client`'s transport with
`NewSignTransport`:

```go
client := http.Client{
	// Wrap the transport:
	Transport: httpsig.NewSignTransport(http.DefaultTransport,
		httpsig.WithSignEcdsaP256Sha256("key1", privKey)),
}

var buf bytes.Buffer

// construct body, etc
// ...

resp, err := client.Post("https://some-url.com", "application/json", &buf)
if err != nil {
	return
}
defer resp.Body.Close()

// ...
```

### Verifying HTTP Requests in Servers

To verify HTTP requests on the server, wrap the `http.Handler`s you wish to
protect with `NewVerifyMiddleware`. `NewVerifyMiddleware` returns the wrapping
func, so you can reuse configuration across multiple handlers.

```go
h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "Your request has an valid signature!")
})

middleware := httpsig.NewVerifyMiddleware(httpsig.WithVerifyEcdsaP256Sha256("key1", pubkey))
http.Handle("/", middleware(h))
```

For more usage examples and documentation, see the [godoc refernce][godoc]

## The Big Feature Matrix

This implementation is based on version `19` of [HTTP Message Signatures][msgsig]
(`draft-ietf-htttpbis-message-signatures-19` from 26 July 2023). Digest
computation is based on version `13` of [Digest Headers][dighdr]
(`draft-ietf-httpbis-digest-headers-13` from 10 July 2023).

| Feature                         |   |   | Notes                                                                  |
| ------------------------------- | - | - | ---------------------------------------------------------------------- |
| sign requests                   | ✅ |   |                                                                        |
| verify requests                 | ✅ |   |                                                                        |
| sign responses                  | ✅ |   |                                                                        |
| verify responses                | ✅ |   |                                                                        |
| add `expires` to signature      | ✅ |   |                                                                        |
| enforce `expires` in verify     | ✅ |   |                                                                        |
| `@method` component             | ✅ |   |                                                                        |
| `@authority` component          | ✅ |   |                                                                        |
| `@scheme` component             | ✅ |   |                                                                        |
| `@target-uri` component         | ✅ |   |                                                                        |
| `@path` component               | ✅ |   |                                                                        |
| `@query` component              | ✅ |   | Encoding handling is missing.                                          |
| `@query-params` component       | ✅ |   |                                                                        |
| `@status` component             | ✅ |   |                                                                        |
| request-response binding        | ✅ |   |                                                                        |
| `Accept-Signature` header       |   | ❌ |                                                                        |
| create multiple signatures      | ✅ |   |                                                                        |
| verify from multiple signatures | ✅ |   |                                                                        |
| `rsa-pss-sha512`                | ✅ |   |                                                                        |
| `rsa-v1_5-sha256`               | ✅ |   |                                                                        |
| `hmac-sha256`                   | ✅ |   |                                                                        |
| `ecdsa-p256-sha256`             | ✅ |   |                                                                        |
| `ecdsa-p384-sha384`             | ✅ |   |                                                                        |
| `ed25519`                       | ✅ |   |                                                                        |
| JSON Web Signatures             |   | ❌ | JWS doesn't support any additional algs, but it is part of the spec    |
| Signature-Input as trailer      |   | ❌ | Trailers can be dropped. accept for verification only.                 |
| Signature as trailer            |   | ❌ | Trailers can be dropped. accept for verification only.                 |
| multiple digests                | ✅ |   |                                                                        |
| digest: `sha-256`               | ✅ |   |                                                                        |
| digest: `sha-512`               | ✅ |   |                                                                        |

## Contributing

I would love your help!

`httpsig` is still a work in progress. You can help by:

- Opening a pull request to resolve an [open issue][issues].
- Adding a feature or enhancement of your own! If it might be big, please
  [open an issue][enhancement] first so we can discuss it.
- Improving this `README` or adding other documentation to `httpsig`.
- Letting [me] know if you're using `httpsig`.

<!-- These are mostly for pkg.go.dev, to show up in the header -->
## Links

- [HTTP Message Signatures standard][msgsig]
- [Digest Headers standard][dighdr]
- [Modern webhook signatures][myblog]

<!-- Other links -->
[go]: https://golang.org
[msgsig]: https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-19.html
[dighdr]: https://www.ietf.org/archive/id/draft-ietf-httpbis-digest-headers-13.html
[myblog]: https://repl.ca/modern-webhook-signatures/

[godoc]: https://pkg.go.dev/github.com/offblocks/httpsig
[issues]: ./issues
[bug]: ./issues/new?labels=bug
[enhancement]: ./issues/new?labels=enhancement

[me]: https://twitter.com/jrbowes
