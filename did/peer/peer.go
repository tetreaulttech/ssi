package peer

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/btcsuite/btcutil/base58"
	"github.com/tetreaulttech/ssi/did"
	"github.com/tetreaulttech/ssi/wallet"
	"time"
)

func New(w wallet.Wallet) (*did.Document, error) {
	pk, err := w.CreateKey(wallet.Ed25519VerificationKey2018Type)
	if err != nil {
		return nil, err
	}

	ddoc := &did.Document{
		Context: "https://www.w3.org/ns/did/v1",
		PublicKey: []did.PublicKey{
			{
				Id:              pk[:8],
				Type:            "Ed25519VerificationKey2018",
				Controller:      "#id",
				PublicKeyBase58: pk,
			},
		},
		Authentication: []interface{}{
			"#" + pk[:8],
		},
		Authorization: did.Authorization{
			Rules: []did.Rule{
				{
					Grant: []string{"register"},
					When:  map[string]interface{}{"id": "#" + pk[:8]},
				},
			},
		},
		Created: time.Now().UTC().Format("2006-01-02T15:04:05Z"), //2002-10-10T17:00:00Z
	}

	ddoc.Authorization.Rules[0].Id, err = generateId(ddoc.Authorization.Rules[0])
	if err != nil {
		return nil, err
	}

	ddoc.Id, err = generateDid(ddoc)
	if err != nil {
		return nil, err
	}

	return ddoc, nil
}

func generateId(o interface{}) (string, error) {
	h := sha256.New()
	if r, err := json.Marshal(o); err != nil {
		return "", err
	} else {
		if _, err := h.Write(r); err != nil {
			return "", err
		}
	}
	return base58.Encode(h.Sum([]byte{})[:8]), nil
}

/* generateDid

Reference: https://openssi.github.io/peer-did-method-spec/index.html#generation-method
*/
func generateDid(o *did.Document) (string, error) {
	hasher := sha256.New()
	if r, err := json.Marshal(o); err != nil {
		return "", err
	} else {
		if _, err := hasher.Write(r); err != nil {
			return "", err
		}
	}

	return "did:peer:1z" + base58.Encode(append([]byte{0x12, 0x20}, hasher.Sum([]byte{})...)), nil
}
