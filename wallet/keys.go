package wallet

import "crypto"

type KeyType string

const Ed25519VerificationKey2018Type KeyType = "Ed25519VerificationKey2018"

type Key interface {
	Sign(id string, data []byte) (signature []byte, err error)
	Verify(crypto.PublicKey, []byte) (signature []byte, err error)
}
