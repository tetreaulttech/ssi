package envelope

import (
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/tetreaulttech/ssi/wallet"
	"log"
	"testing"
)

func TestPackAndUnpackAuthenticated(t *testing.T) {
	aliceWallet, err := wallet.NewWallet("supersecret", wallet.NewInMemoryStorage())
	if err != nil {
		t.Error(err.Error())
		return
	}

	aliceKey, err := aliceWallet.CreateKey(wallet.Ed25519VerificationKey2018Type)
	if err != nil {
		t.Error(err.Error())
		return
	}

	bobWallet, err := wallet.NewWallet("supersecret", wallet.NewInMemoryStorage())
	if err != nil {
		t.Error(err.Error())
		return
	}

	bobKey, err := bobWallet.CreateKey(wallet.Ed25519VerificationKey2018Type)
	if err != nil {
		t.Error(err.Error())
		return
	}

	packed, err := Pack(aliceWallet, []byte("oh hey there!"), []string{bobKey}, aliceKey)
	if err != nil {
		t.Error(err.Error())
		return
	}

	log.Println(string(packed))

	msg, err := Unpack(bobWallet, packed)
	if err != nil {
		t.Error(err.Error())
		return
	}

	log.Println(string(msg))
}

func TestPackAndUnpackAnonymous(t *testing.T) {
	aliceWallet, err := wallet.NewWallet("supersecret", wallet.NewInMemoryStorage())
	if err != nil {
		t.Error(err.Error())
		return
	}

	aliceKey, err := aliceWallet.CreateKey(wallet.Ed25519VerificationKey2018Type)
	if err != nil {
		t.Error(err.Error())
		return
	}

	packed, err := Pack(aliceWallet, []byte("oh hey there!"), []string{aliceKey}, "")
	if err != nil {
		t.Error(err.Error())
		return
	}

	e := new(envelope)
	_ = json.Unmarshal(packed, e)
	pEnc, _ := base64.URLEncoding.DecodeString(e.Protected)
	p := new(protected)
	_ = json.Unmarshal(pEnc, p)
	assert.Equal(t, anoncrypt, p.Alg)

	log.Println(string(packed))

	msg, err := Unpack(aliceWallet, packed)
	if err != nil {
		t.Error(err.Error())
		return
	}

	log.Println(string(msg))
}

func TestUnpackSignedUnencrypted(t *testing.T) {

}
