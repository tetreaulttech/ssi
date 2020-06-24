package peer

import (
	"encoding/json"
	"github.com/tetreaulttech/ssi/wallet"
	"log"
	"testing"
)

func TestNew(t *testing.T) {
	aliceWallet, err := wallet.NewWallet("supersecret", wallet.NewInMemoryStorage())
	if err != nil {
		t.Error(err.Error())
		return
	}

	ddoc, err := New(aliceWallet)
	if err != nil {
		t.Error(err.Error())
		return
	}

	b, _ := json.MarshalIndent(ddoc, "", "\t")
	log.Println(string(b))
}
