package envelope

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/tetreaulttech/ssi/wallet"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"io"
)

// Wrap a plaintext message in an encrypted envelope
//
// handle: handle to the wallet that contains the sender's secrets.
//
// message: the message (plaintext, or nested encrypted envelope) as a string.
//          If it's JSON object it should be in string format first
//
// receiverKeys: a list of recipient keys as string containing a JSON array
//
// senderKey: the sender's key as a string. This key is used to look up the sender's
//            private key so the wallet can put supply it as input to the encryption
//            algorithm. When an empty string ("") is passed in this parameter,
//            anoncrypt mode is used
func Pack(handle wallet.Wallet, message []byte, receiverKeys []string, senderKey string) ([]byte, error) {
	p := protected{
		Enc:        xchacha20poly1305_ietf,
		Typ:        "JWM/1.0",
		Recipients: make([]recipient, len(receiverKeys)),
	}

	// 1. generate a content encryption key (symmetrical encryption key)
	var contentEncryptionKey [chacha20poly1305.KeySize]byte
	if _, err := io.ReadFull(rand.Reader, contentEncryptionKey[:]); err != nil {
		return nil, err
	}

	for i, receiverKey := range receiverKeys {
		var encrypted, sender []byte
		var nonce [24]byte
		var err error
		if senderKey != "" {
			// 2. encrypt the CEK for each recipient's public key using Authcrypt (steps below)
			// 		i. set encrypted_key value to base64URLencode(libsodium.crypto_box(my_key, their_vk, cek, cek_iv))
			//			Note it this step we're encrypting the cek, so it can be decrypted by the recipient
			//		ii. set sender value to base64URLencode(libsodium.crypto_box_seal(their_vk, sender_vk_string))
			//			Note in this step we're encrypting the senderKey to protect sender anonymity
			//		iii. base64URLencode(cek_iv) and set to iv value in the header
			//			Note the cek_iv in the header is used for the encrypted_key where as iv is for ciphertext
			p.Alg = authcrypt

			encrypted, nonce, err = handle.Seal(contentEncryptionKey[:], receiverKey, senderKey)
			if err != nil {
				return nil, err
			}

			sender, err = handle.SealAnonymous([]byte(senderKey), receiverKey)
			if err != nil {
				return nil, err
			}

			p.Recipients[i] = recipient{
				EncryptedKey: base64.URLEncoding.EncodeToString(encrypted),
				Header: header{
					Kid:    receiverKey,
					Iv:     base64.URLEncoding.EncodeToString(nonce[:]),
					Sender: base64.URLEncoding.EncodeToString(sender),
				},
			}
		} else {
			// 2. encrypt the CEK for each recipient's public key using Anoncrypt
			//    set encrypted_key value to base64URLencode(libsodium.crypto_box_seal(their_vk, cek))
			//        Note it this step we're encrypting the cek, so it can be decrypted by the recipient
			p.Alg = anoncrypt

			encrypted, err = handle.SealAnonymous(contentEncryptionKey[:], receiverKey)

			p.Recipients[i] = recipient{
				EncryptedKey: base64.URLEncoding.EncodeToString(encrypted),
				Header: header{
					Kid: receiverKey,
				},
			}
		}

	}

	// 3. base64URLencode the protected value
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	pEnc := base64.URLEncoding.EncodeToString(b)

	// 4. encrypt the message using libsodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(message, protected_value_encoded, iv, cek) this is the ciphertext.
	var iv [chacha20poly1305.NonceSizeX]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(contentEncryptionKey[:])
	if err != nil {
		panic(err)
	}

	encryptedMsg := aead.Seal([]byte{}, iv[:], message, []byte(pEnc))

	// 5. base64URLencode the iv, ciphertext, and tag then serialize the format into the output format listed above.
	packed := envelope{
		Protected:  pEnc,
		Iv:         base64.URLEncoding.EncodeToString(iv[:]),
		Ciphertext: base64.URLEncoding.EncodeToString(encryptedMsg[:len(encryptedMsg)-poly1305.TagSize]),
		Tag:        base64.URLEncoding.EncodeToString(encryptedMsg[len(encryptedMsg)-poly1305.TagSize:]),
	}

	return json.Marshal(packed)
}

// Unwrap encrypted envelopes in to the plaintext messages
//
// handle: wallet handle that contains the sender key
//
// message: an encrypted message envelope which follows the scheme format described here:
//      https://github.com/hyperledger/aries-rfcs/blob/master/features/0019-encryption-envelope/schema.md
func Unpack(handle wallet.Wallet, packed []byte) (msg []byte, err error) {
	// 1. Serialize data, so it can be used
	var e envelope
	if err = json.Unmarshal(packed, &e); err != nil {
		return
	}

	p := protected{}
	if err = decodeAndUnmarshal(e.Protected, &p); err != nil {
		return
	}

	var contentEncryptionKey []byte
	{
		for _, recipient := range p.Recipients {
			// 2. Lookup the kid for each recipient in the wallet to see if the wallet possesses a private key associated with the public key listed
			if !handle.KeyExists(recipient.Header.Kid) {
				continue
			}

			ekey, err := base64.URLEncoding.DecodeString(recipient.EncryptedKey)
			if err != nil {
				return nil, err
			}

			// 3. Check if a sender field is used.
			//		If a sender is included use auth_decrypt to decrypt the encrypted_key by doing the following:
			//			decrypt sender verkey using libsodium.crypto_box_seal_open(my_private_key, base64URLdecode(sender))
			//			decrypt cek using libsodium.crypto_box_open(my_private_key, senderKey, encrypted_key, cek_iv)
			//			decrypt ciphertext using libsodium.crypto_aead_chacha20poly1305_ietf_open_detached(base64URLdecode(ciphertext_bytes), base64URLdecode(protected_data_as_bytes), base64URLdecode(nonce), cek)
			//			return message, recipientKey and senderKey following the authcrypt format
			if recipient.Header.Sender != "" {
				eSender, err := base64.URLEncoding.DecodeString(recipient.Header.Sender)
				if err != nil {
					return nil, err
				}

				sender, res := handle.OpenAnonymous(eSender, recipient.Header.Kid)
				if !res {
					return nil, errors.New("unable to open sender box")
				}

				iv, err := base64.URLEncoding.DecodeString(recipient.Header.Iv)
				if err != nil {
					return nil, err
				}

				contentEncryptionKey, res = handle.Open(ekey, iv, string(sender), recipient.Header.Kid)
				if !res {
					return nil, errors.New("unable to open content encryption key box")
				}
			} else {
				//		If a sender is NOT included use anon_decrypt to decrypt the encrypted_key by doing the following:
				//			decrypt encrypted_key using libsodium.crypto_box_seal_open(my_private_key, encrypted_key)
				//			decrypt ciphertext using libsodium.crypto_aead_chacha20poly1305_ietf_open_detached(base64URLdecode(ciphertext_bytes), base64URLdecode(protected_data_as_bytes), base64URLdecode(nonce), cek)
				//			return message and recipientKey following the anoncrypt format
				var res bool
				contentEncryptionKey, res = handle.OpenAnonymous(ekey, recipient.Header.Kid)
				if !res {
					return nil, errors.New("unable to open content encryption key box")
				}
			}
		}

		if len(contentEncryptionKey) == 0 {
			return nil, errors.New("no matching keys")
		}
	}

	var iv []byte
	if iv, err = base64.URLEncoding.DecodeString(e.Iv); err != nil {
		return
	}

	var ciphertext []byte
	if ciphertext, err = base64.URLEncoding.DecodeString(e.Ciphertext); err != nil {
		return
	}

	var tag []byte
	if tag, err = base64.URLEncoding.DecodeString(e.Tag); err != nil {
		return
	}

	aead, err := chacha20poly1305.NewX(contentEncryptionKey[:])
	if err != nil {
		panic(err)
	}

	return aead.Open([]byte{}, iv[:], append(ciphertext, tag...), []byte(e.Protected))
}

func decodeAndUnmarshal(src string, dst interface{}) error {
	if d, err := base64.URLEncoding.DecodeString(src); err != nil {
		return err
	} else {
		if err := json.Unmarshal(d, dst); err != nil {
			return err
		}
	}
	return nil
}
