package envelope

type cipher string

const xchacha20poly1305_ietf cipher = "xchacha20poly1305_ietf"

type algorithm string

const authcrypt algorithm = "authcrypt"
const anoncrypt algorithm = "anoncrypt"

type header struct {
	Kid    string `json:"kid",validate:"nonzero"` // base58 encoded verkey of the recipient.
	Sender string `json:"sender"`
	Iv     string `json:"iv"`
}

type recipient struct {
	// The key used for encrypting the ciphertext. This is also referred to as a cek
	EncryptedKey string `json:"encrypted_key",validate:"nonzero"`
	// The recipient to whom this message will be sent
	Header header `json:"header",validate:"nonzero"`
}

type protected struct {
	// The authenticated encryption algorithm used to encrypt the ciphertext
	Enc cipher `json:"enc",validate:"nonzero"`
	// The message type. Ex: JWM/1.0
	Typ string `json:"typ",validate:"nonzero"`
	// The message packing algorithm, e.g.: authcrypt or anoncrypt
	Alg algorithm `json:"alg",validate:"nonzero"`
	// A list of the recipients who the message is encrypted for
	Recipients []recipient `json:"recipients",validate:"min=1"`
}

// Json Web Message format
// Reference: https://github.com/hyperledger/aries-rfcs/blob/master/features/0019-encryption-envelope/schema.md
type envelope struct {
	// Additional authenticated message data base64URL encoded, so it can be verified by the recipient using the tag
	Protected string `json:"protected",validate:"nonzero"`
	// base64 URL encoded nonce used to encrypt ciphertext
	Iv string `json:"iv",validate:"nonzero"`
	// base64 URL encoded authenticated encrypted message
	Ciphertext string `json:"ciphertext",validate:"nonzero"`
	// Integrity checksum/tag base64URL encoded to check ciphertext, protected, and iv
	Tag string `json:"tag",validate:"nonzero"`
}
