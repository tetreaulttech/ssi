package web

import (
	"fmt"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/tetreaulttech/ssi/did"
	"testing"
)

const validDid = "did:web:example.com"
const notFoundDid = "did:web:not.found"
const invalidJsonDid = "did:web:in.valid"
const wrongIdDid = "did:web:wrong.id"
const missingKeysDid = "did:web:no.keys"
const longDid = "did:web:example.com:user:alice"
const identity = "0x2Cc31912B2b0f3075A87b3640923D45A26cef3Ee"

var validResponse = did.Document{
	Context: "https://w3id.org/did/v1",
	Id:      validDid,
	PublicKey: []did.PublicKey{
		{Id: fmt.Sprintf("%s#owner", validDid), Type: "Secp256k1VerificationKey2018", Controller: validDid, EthereumAddress: identity},
	},
	Authentication: []interface{}{
		did.Authentication{Type: "Secp256k1SignatureAuthentication2018", PublicKey: fmt.Sprintf("%s#owner", validDid)},
	},
	Service: nil,
	Created: "",
	Updated: "",
}

var validResponseLong = did.Document{
	Context: "https://w3id.org/did/v1",
	Id:      longDid,
	PublicKey: []did.PublicKey{
		{Id: fmt.Sprintf("%s#owner", validDid), Type: "Secp256k1VerificationKey2018", Controller: validDid, EthereumAddress: identity},
	},
	Authentication: []interface{}{
		did.Authentication{Type: "Secp256k1SignatureAuthentication2018", PublicKey: fmt.Sprintf("%s#owner", longDid)},
	},
	Service: nil,
	Created: "",
	Updated: "",
}

var noContextResponse = did.Document{
	Id:             validResponse.Id,
	PublicKey:      validResponse.PublicKey,
	Authentication: validResponse.Authentication,
}

var noPublicKeyResponse = did.Document{
	Context:        validResponse.Context,
	Id:             missingKeysDid,
	Authentication: validResponse.Authentication,
}

func TestResolver(t *testing.T) {
	resolver := New()
	httpmock.ActivateNonDefault(resolver.resty.GetClient())
	defer httpmock.DeactivateAndReset()

	if r, err := httpmock.NewJsonResponder(200, validResponse); err == nil {
		httpmock.RegisterResponder("GET", "https://example.com/.well-known/did.json", r)
	}

	if r, err := httpmock.NewJsonResponder(200, validResponseLong); err == nil {
		httpmock.RegisterResponder("GET", "https://example.com/user/alice/did.json", r)
	}

	httpmock.RegisterResponder("GET", "https://in.valid/.well-known/did.json", httpmock.NewStringResponder(200, "invalid json"))

	if r, err := httpmock.NewJsonResponder(200, validResponseLong); err == nil {
		httpmock.RegisterResponder("GET", "https://wrong.id/.well-known/did.json", r)
	}

	if r, err := httpmock.NewJsonResponder(200, noPublicKeyResponse); err == nil {
		httpmock.RegisterResponder("GET", "https://no.keys/.well-known/did.json", r)
	}

	tests := []struct {
		name                string
		did                 string
		expectedDidDocument *did.Document
		expectedError       bool
	}{
		{name: "resolves document", did: validDid, expectedDidDocument: &validResponse},
		{name: "resolves long document", did: longDid, expectedDidDocument: &validResponseLong},
		{name: "fails if not found", did: notFoundDid, expectedDidDocument: nil, expectedError: true},
		{name: "fails if invalid json", did: invalidJsonDid, expectedDidDocument: nil, expectedError: true},
		{name: "fails if did does not match requested", did: wrongIdDid, expectedDidDocument: nil, expectedError: true},
		{name: "fails if document has no public keys", did: missingKeysDid, expectedDidDocument: nil, expectedError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ddoc, err := resolver.Resolve(tt.did)
			assert.EqualValues(t, tt.expectedDidDocument, ddoc)
			if tt.expectedError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}

}