package wallet

import (
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/chacha20poly1305"
)

type metadata struct {
	TagNameKey  []byte `json:"tagNameKey"`
	TagValueKey []byte `json:"tagValueKey"`
	HmacKey     []byte `json:"hmacKey"`
	TypeKey     []byte `json:"typeKey"`
	NameKey     []byte `json:"nameKey"`
	ItemKeyKey  []byte `json:"valueKeyKey"`
}

type encodedMetadata struct {
	TagNameKey  string `json:"tagNameKey"`
	TagValueKey string `json:"tagValueKey"`
	HmacKey     string `json:"hmacKey"`
	TypeKey     string `json:"typeKey"`
	NameKey     string `json:"nameKey"`
	ValueKeyKey string `json:"valueKeyKey"`
}

func (m *metadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(encodedMetadata{
		TagNameKey:  base64.StdEncoding.EncodeToString(m.TagNameKey),
		TagValueKey: base64.StdEncoding.EncodeToString(m.TagValueKey),
		HmacKey:     base64.StdEncoding.EncodeToString(m.HmacKey),
		TypeKey:     base64.StdEncoding.EncodeToString(m.TypeKey),
		NameKey:     base64.StdEncoding.EncodeToString(m.NameKey),
		ValueKeyKey: base64.StdEncoding.EncodeToString(m.ItemKeyKey),
	})
}

func (m *metadata) UnmarshalJSON(b []byte) error {
	e := encodedMetadata{}
	err := json.Unmarshal(b, &e)
	if err != nil {
		return err
	}

	m.TagNameKey = make([]byte, chacha20poly1305.KeySize)
	m.TagValueKey = make([]byte, chacha20poly1305.KeySize)
	m.HmacKey = make([]byte, 64)
	m.TypeKey = make([]byte, chacha20poly1305.KeySize)
	m.NameKey = make([]byte, chacha20poly1305.KeySize)
	m.ItemKeyKey = make([]byte, chacha20poly1305.KeySize)

	_, err = base64.StdEncoding.Decode(m.TagNameKey, []byte(e.TagNameKey))
	if err != nil {
		return err
	}
	_, err = base64.StdEncoding.Decode(m.TagValueKey, []byte(e.TagValueKey))
	if err != nil {
		return err
	}
	_, err = base64.StdEncoding.Decode(m.HmacKey, []byte(e.HmacKey))
	if err != nil {
		return err
	}
	_, err = base64.StdEncoding.Decode(m.TypeKey, []byte(e.TypeKey))
	if err != nil {
		return err
	}
	_, err = base64.StdEncoding.Decode(m.NameKey, []byte(e.NameKey))
	if err != nil {
		return err
	}
	_, err = base64.StdEncoding.Decode(m.ItemKeyKey, []byte(e.ValueKeyKey))
	if err != nil {
		return err
	}
	return nil
}

const metadataId = "metadata"
