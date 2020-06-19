package wallet

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/teserakt-io/golang-ed25519/extra25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"strings"
)

type Wallet interface {
	Create(id string, item interface{}) error
	Read(id string, out interface{}) error
	Update(id string, item interface{}) error
	Delete(id string) error

	CreateKey(typ KeyType) (string, error)
	DeleteKey(id string) error
	KeyExists(id string) bool

	Encrypt(id string, data []byte) (ciphertext []byte, err error)
	Decrypt(id string, ciphertext []byte) (data []byte, err error)

	Sign(id string, data []byte) ([]byte, error)
	Verify(id string, data []byte, sig []byte) bool

	Seal(message []byte, receiverKey, senderKey string) (encrypted []byte, nonce [24]byte, err error)
	SealAnonymous(message []byte, receiverKey string) (encrypted []byte, err error)
	Open(ciphertext []byte, nonce []byte, senderKey, receiverKey string) (plaintext []byte, res bool)
	OpenAnonymous(ciphertext []byte, receiverKey string) (plaintext []byte, res bool)
}

type wallet struct {
	metadata *metadata
	storage  Storage
	wrapper  Wrapper
}

func NewWallet(password string, s Storage) (Wallet, error) {
	masterKey := pbkdf2.Key([]byte(password), []byte("saltsaltsaltsalt"), 100000, 32, crypto.SHA512.New)

	var metadata *metadata

	m, err := s.read(metadataId)
	if err == ErrorNotFound {
		metadata, err = generateMetadata(masterKey, s)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		metadata, err = decryptMetadata(m, masterKey)
		if err != nil {
			return nil, err
		}
	}

	return &wallet{storage: s, metadata: metadata}, nil
}

func NewWalletWithWrapper(password string, storage Storage, wrapper Wrapper) (Wallet, error) {
	return &wallet{storage: storage, wrapper: wrapper}, nil
}

func (w *wallet) Create(id string, i interface{}) error {
	eid, err := encryptSearcheable(w.metadata.NameKey, w.metadata.HmacKey, []byte(id))
	if err != nil {
		return err
	}

	valueKey := make([]byte, chacha20poly1305.KeySize)
	_, err = rand.Read(valueKey)
	if err != nil {
		return err
	}

	m, err := json.Marshal(i)
	if err != nil {
		return err
	}

	eitem, err := encrypt(valueKey, m)
	if err != nil {
		return err
	}

	evalueKey, err := encrypt(w.metadata.ItemKeyKey, valueKey)
	if err != nil {
		return err
	}

	storageItem := item{
		ID:      eid,
		Item:    eitem,
		ItemKey: evalueKey,
	}

	return w.storage.create(storageItem)
}

func (w *wallet) Read(id string, out interface{}) error {
	if strings.HasPrefix(id, "_local/") {
		return errors.New("item cannot be extracted")
	}

	return w.read(id, out)
}

func (w *wallet) read(id string, out interface{}) error {
	eid, err := encryptSearcheable(w.metadata.NameKey, w.metadata.HmacKey, []byte(id))
	if err != nil {
		return err
	}

	storageItem, err := w.storage.read(eid)
	if err != nil {
		return err
	}

	itemKey, err := decrypt(w.metadata.ItemKeyKey, storageItem.ItemKey)
	if err != nil {
		return err
	}

	item, err := decrypt(itemKey, storageItem.Item)
	if err != nil {
		return err
	}

	return json.Unmarshal(item, out)
}

func (w *wallet) Update(id string, i interface{}) error {
	eid, err := encryptSearcheable(w.metadata.NameKey, w.metadata.HmacKey, []byte(id))
	if err != nil {
		return err
	}

	valueKey := make([]byte, chacha20poly1305.KeySize)
	_, err = rand.Read(valueKey)
	if err != nil {
		return err
	}

	m, err := json.Marshal(i)
	if err != nil {
		return err
	}

	eitem, err := encrypt(valueKey, m)
	if err != nil {
		return err
	}

	evalueKey, err := encrypt(w.metadata.ItemKeyKey, valueKey)
	if err != nil {
		return err
	}

	storageItem := item{
		ID:      eid,
		Item:    eitem,
		ItemKey: evalueKey,
	}

	return w.storage.update(storageItem)
}

func (w *wallet) Delete(id string) error {
	eid, err := encryptSearcheable(w.metadata.NameKey, w.metadata.HmacKey, []byte(id))
	if err != nil {
		return err
	}
	return w.storage.delete(eid)
}

func (w *wallet) CreateKey(typ KeyType) (string, error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	enc := base58.Encode(pk)
	err = w.Create("_local/"+enc, sk)
	return enc, err
}

func (w *wallet) DeleteKey(id string) error {
	return w.Delete("_local/" + id)
}

func (w *wallet) KeyExists(id string) bool {
	if err := w.read("_local/"+id, &ed25519.PrivateKey{}); err != nil {
		return false
	}
	return true
}

func (w *wallet) Encrypt(id string, data []byte) (ciphertext []byte, err error) {
	panic("not implemented")
}

func (w *wallet) Decrypt(id string, ciphertext []byte) (data []byte, err error) {
	panic("not implemented")
}

func (w *wallet) Sign(id string, data []byte) ([]byte, error) {
	var sk ed25519.PrivateKey
	err := w.read("_local/"+id, &sk)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(sk, data), nil
}

func (w *wallet) Verify(id string, msg []byte, sig []byte) bool {
	var sk ed25519.PrivateKey
	err := w.read("_local/"+id, &sk)
	if err != nil {
		return false
	}
	return ed25519.Verify(sk.Public().(ed25519.PublicKey), msg, sig)
}

func (w *wallet) Seal(message []byte, receiverKey, senderKey string) (encrypted []byte, nonce [24]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}

	d := base58.Decode(receiverKey)
	pk := new([32]byte)
	copy(pk[:], d[:32])

	var curve25519pk [32]byte
	extra25519.PublicKeyToCurve25519(&curve25519pk, pk)

	var key ed25519.PrivateKey
	if err = w.read("_local/"+senderKey, &key); err != nil {
		return
	}
	sk := new([64]byte)
	copy(sk[:], key[:64])

	var curve25519sk [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519sk, sk)

	encrypted = box.Seal([]byte{}, message, &nonce, &curve25519pk, &curve25519sk)
	return
}

func (w *wallet) Open(ciphertext []byte, nonce []byte, senderKey, receiverKey string) (plaintext []byte, res bool) {
	var key ed25519.PrivateKey
	if err := w.read("_local/"+receiverKey, &key); err != nil {
		return nil, false
	}
	sk := new([64]byte)
	copy(sk[:], key[:64])

	var curve25519sk [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519sk, sk)

	d := base58.Decode(senderKey)
	pk := new([32]byte)
	copy(pk[:], d[:32])

	var curve25519pk [32]byte
	extra25519.PublicKeyToCurve25519(&curve25519pk, pk)

	n := new([chacha20poly1305.NonceSizeX]byte)
	copy(n[:], nonce[:chacha20poly1305.NonceSizeX])

	return box.Open([]byte{}, ciphertext, n, &curve25519pk, &curve25519sk)
}

func (w *wallet) SealAnonymous(message []byte, receiverKey string) (encrypted []byte, err error) {
	d := base58.Decode(receiverKey)
	pk := new([32]byte)
	copy(pk[:], d[:32])

	var curve25519pk [32]byte
	extra25519.PublicKeyToCurve25519(&curve25519pk, pk)

	return box.SealAnonymous([]byte{}, message, &curve25519pk, rand.Reader)
}

func (w *wallet) OpenAnonymous(ciphertext []byte, receiverKey string) (plaintext []byte, res bool) {
	var key ed25519.PrivateKey
	if err := w.read("_local/"+receiverKey, &key); err != nil {
		return nil, false
	}
	sk := new([64]byte)
	copy(sk[:], key[:64])

	var curve25519sk [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519sk, sk)

	d := base58.Decode(receiverKey)
	pk := new([32]byte)
	copy(pk[:], d[:32])

	var curve25519pk [32]byte
	extra25519.PublicKeyToCurve25519(&curve25519pk, pk)

	return box.OpenAnonymous([]byte{}, ciphertext, &curve25519pk, &curve25519sk)
}

func decryptMetadata(m item, key []byte) (*metadata, error) {
	b, err := decrypt(key, m.Item)
	if err != nil {
		return nil, err
	}
	var metadata metadata
	err = json.Unmarshal(b, &metadata)
	return &metadata, err
}

func generateMetadata(key []byte, s Storage) (*metadata, error) {
	metadata := metadata{
		TagNameKey:  make([]byte, chacha20poly1305.KeySize),
		TagValueKey: make([]byte, chacha20poly1305.KeySize),
		HmacKey:     make([]byte, 64),
		TypeKey:     make([]byte, chacha20poly1305.KeySize),
		NameKey:     make([]byte, chacha20poly1305.KeySize),
		ItemKeyKey:  make([]byte, chacha20poly1305.KeySize),
	}

	_, err := rand.Read(metadata.TagNameKey)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(metadata.TagValueKey)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(metadata.HmacKey)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(metadata.TypeKey)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(metadata.NameKey)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(metadata.ItemKeyKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		return nil, err
	}

	storageItem := item{
		ID:   "metadata",
		Item: ciphertext,
	}

	err = s.create(storageItem)
	return &metadata, err
}

func encrypt(key []byte, plaintext []byte) (string, error) {
	name, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}

	ciphertext := name.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func encryptSearcheable(key []byte, hmacKey []byte, plaintext []byte) (string, error) {
	name, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	h := hmac.New(crypto.SHA512.New, hmacKey)
	h.Write(plaintext)
	nonce := h.Sum(nil)

	ciphertext := name.Seal(nil, nonce[:chacha20poly1305.NonceSizeX], []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func decrypt(key []byte, ciphertext string) ([]byte, error) {
	decodedCiphertext, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	name, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return name.Open(nil, decodedCiphertext[:chacha20poly1305.NonceSizeX], decodedCiphertext[chacha20poly1305.NonceSizeX:], nil)
}
