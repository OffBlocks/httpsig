package httpsig

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

type signatureItem struct {
	key   httpsfv.Item
	value httpsfv.StructuredFieldValue
}

func createSigningParameters(config *SignConfig) *httpsfv.Params {
	// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures#name-signature-parameters

	now := time.Now()

	params := config.Params
	if len(params) == 0 {
		params = defaultParams
	}

	output := httpsfv.NewParams()

	if slices.Contains(params, ParamCreated) {
		// created is optional but recommended. If created is supplied but is nil, that's an explicit
		// instruction to *not* include the created parameter
		var created *time.Time
		if config.ParamValues != nil && config.ParamValues.Created == nil {
			created = nil
		} else if config.ParamValues != nil && config.ParamValues.Created != nil {
			created = config.ParamValues.Created
		} else {
			created = &now
		}
		if created != nil {
			output.Add("created", created.Unix())
		}
	}

	if slices.Contains(params, ParamExpires) {
		// attempt to obtain an explicit expires time, otherwise create one that is 300 seconds after
		// creation. Don't add an expires time if there is no created time
		var expires *time.Time
		if config.ParamValues != nil && config.ParamValues.Expires != nil && config.ParamValues.Created != nil {
			expires = config.ParamValues.Expires
		} else if config.ParamValues != nil && config.ParamValues.Created != nil {
			exp := now.Add(300 * time.Second)
			expires = &exp
		}
		if expires != nil {
			output.Add("expires", expires.Unix())
		}
	}

	if slices.Contains(params, ParamKeyID) {
		// attempt to obtain an overriden key id, otherwise use the one supplied by the key
		var keyID *string
		if config.ParamValues != nil && config.ParamValues.KeyID != nil {
			keyID = config.ParamValues.KeyID
		} else {
			k := config.Key.GetKeyID()
			keyID = &k
		}
		output.Add("keyid", *keyID)
	}

	if slices.Contains(params, ParamAlg) {
		// attempt to obtain an overriden algorithm, otherwise use the one supplied by the key
		var alg *Algorithm
		if config.ParamValues != nil && config.ParamValues.Alg != nil {
			alg = config.ParamValues.Alg
		} else {
			a := config.Key.GetAlgorithm()
			alg = &a
		}
		output.Add("alg", string(*alg))
	}

	if slices.Contains(params, ParamNonce) {
		// attempt to obtain an explicit nonce, otherwise create one
		var n *string
		if config.ParamValues != nil && config.ParamValues.Nonce != nil {
			n = config.ParamValues.Nonce
		} else {
			nonce := nonce()
			n = &nonce
		}
		output.Add("nonce", *n)
	}

	if slices.Contains(params, ParamTag) {
		var tag *string
		if config.ParamValues != nil {
			tag = config.ParamValues.Tag
		}
		output.Add("tag", *tag)
	}

	return output
}

func parseParams(params *httpsfv.Params) (*SignatureParameters, error) {
	output := SignatureParameters{}

	if params == nil {
		return nil, errors.New("no parameters provided")
	}

	for _, k := range params.Names() {
		p, _ := params.Get(k)

		if k == "created" {
			if v, ok := p.(int64); ok {
				t := time.Unix(v, 0)
				output.Created = &t
			} else {
				return nil, errors.New("invalid created parameter")
			}
		} else if k == "expires" {
			if v, ok := p.(int64); ok {
				t := time.Unix(v, 0)
				output.Expires = &t
			} else {
				return nil, errors.New("invalid expires parameter")
			}
		} else if k == "nonce" {
			if v, ok := p.(string); ok {
				output.Nonce = &v
			} else {
				return nil, errors.New("invalid nonce parameter")
			}
		} else if k == "alg" {
			if v, ok := p.(string); ok {
				a := Algorithm(v)
				output.Alg = &a
			} else {
				return nil, errors.New("invalid alg parameter")
			}
		} else if k == "keyid" {
			if v, ok := p.(string); ok {
				output.KeyID = &v
			} else {
				return nil, errors.New("invalid keyid parameter")
			}
		} else if k == "tag" {
			if v, ok := p.(string); ok {
				output.Tag = &v
			} else {
				return nil, errors.New("invalid tag parameter")
			}
		} else {
			return nil, errors.New("unknown parameter")
		}
	}

	return &output, nil
}

func normaliseParams(params *httpsfv.Params) *httpsfv.Params {
	if params == nil {
		return nil
	}

	ps := httpsfv.NewParams()

	for _, k := range params.Names() {
		p, _ := params.Get(k)

		if v, ok := p.([]byte); ok {
			encoded := base64.StdEncoding.EncodeToString(v)
			ps.Add(k, encoded)
		} else if v, ok := p.(httpsfv.Token); ok {
			ps.Add(k, string(v))
		} else {
			ps.Add(k, p)
		}
	}

	return ps
}

func createSignatureBase(fields []string, msg *Message) ([]signatureItem, error) {
	items := make([]signatureItem, 0)
	for _, f := range fields {
		field, err := httpsfv.UnmarshalItem([]string{quoteString(f)})
		if err != nil {
			return nil, err
		}

		params := normaliseParams(field.Params)
		lcName := strings.ToLower(field.Value.(string))

		if lcName != "@signature-params" {
			var value httpsfv.StructuredFieldValue
			if strings.HasPrefix(lcName, "@") {
				value, err = canonicaliseComponent(lcName, params, msg)
			} else {
				value, err = canonicaliseHeader(lcName, params, msg)
			}
			if err != nil {
				return nil, err
			}
			item := httpsfv.NewItem(field.Value)
			item.Params = params

			items = append(items, signatureItem{item, value})
		}
	}

	return items, nil
}
