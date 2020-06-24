package web

import (
	"errors"
	"github.com/go-resty/resty/v2"
	"github.com/mitchellh/mapstructure"
	"github.com/tetreaulttech/ssi/did"
	"net/http"
	"net/url"
	"strings"
)

type resolver struct {
	resty *resty.Client
}

func New() *resolver {
	return &resolver{resty: resty.New()}
}

/*
	Resolve a did:web did document.

	Reference: https://w3c-ccg.github.io/did-method-web/

	The following steps must be executed to resolve the DID document from a resolver DID:
    	- Replace ":" with "/" in the method specific identifier to obtain the fully qualified domain name and optional
		  path.
	    - Generate an HTTPS URL to the expected location of the DID document by prepending `https://`.
	    - If no path has been specified in the URL, append `/.well-known`.
	    - Append `/did.json` to complete the URL.
 		- Perform an HTTP `GET` request to the URL using an agent that can successfully negotiate a secure HTTPS
          connection, which enforces the security requirements as described in [Security Considerations](Security-Considerations).
*/
func (d *resolver) Resolve(id string) (*did.Document, error) {
	u, err := url.Parse("https://" + strings.ReplaceAll(id[8:], ":", "/"))
	if err != nil {
		return nil, err
	}

	if u.Path == "" {
		u.Path = "/.well-known"
	}

	u.Path = u.Path + "/did.json"

	var ddoc did.Document
	{
		resp, err := d.resty.R().
			ForceContentType("application/json").
			SetResult(&ddoc).
			Get(u.String())

		if err != nil {
			return nil, err
		}
		if resp.IsError() {
			return nil, errors.New(http.StatusText(resp.StatusCode()))
		}
		if ddoc.Id != id {
			return nil, errors.New("DID does not match requested DID")
		}
		if ddoc.PublicKey == nil || len(ddoc.PublicKey) == 0 {
			return nil, errors.New("DID document has no public keys")
		}
	}

	for i, a := range ddoc.Authentication {
		if m, ok := a.(map[string]interface{}); ok {
			auth := did.Authentication{}
			mapstructure.Decode(m, &auth)
			ddoc.Authentication[i] = auth
		}
	}

	return &ddoc, nil
}
