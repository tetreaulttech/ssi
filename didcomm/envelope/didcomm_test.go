package envelope

import (
	"github.com/tetreaulttech/wallet"
	"log"
	"testing"
)

func TestPackAndUnpack(t *testing.T) {
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
