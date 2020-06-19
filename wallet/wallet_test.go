package wallet

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/go-resty/resty/v2"
	"testing"
)

type testObj struct {
	A string `json:"a"`
}

type TestStorage struct {
	Name     string
	Setup    func() Storage
	Teardown func()
}

func TestSuite(t *testing.T) {

	ims := TestStorage{}
	ims.Name = "In Memory"
	ims.Setup = func() Storage { return NewInMemoryStorage() }
	ims.Teardown = func() {}

	cdb := TestStorage{}
	cdb.Name = "CouchDB"
	cdb.Setup = func() Storage {
		c, err := NewCouchDbStorage("test")
		if err != nil {
			t.Fatalf(err.Error())
		}
		return c
	}
	cdb.Teardown = func() {
		resty.New().R().Delete("http://localhost:5984/test")
	}

	for _, db := range []TestStorage{
		ims,
		cdb,
	} {

		t.Run(db.Name, func(t *testing.T) {

			db.Teardown()

			t.Run("TestCanStoreItemInWallet", func(t *testing.T) {
				s := db.Setup()
				w, err := NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				input := testObj{A: "b"}
				err = w.Create("uniqueid", input)
				if err != nil {
					t.Fatal(err.Error())
				}

				var output testObj
				err = w.Read("uniqueid", &output)
				if err != nil {
					t.Fatal(err.Error())
				}
				if output != input {
					t.Fatalf("Expected: %s, Actual: %s", input, output)
				}
			})

			db.Teardown()

			t.Run("TestCanReopenWallet", func(t *testing.T) {
				s := db.Setup()
				w, err := NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				input := testObj{A: "b"}
				err = w.Create("uniqueid", input)
				if err != nil {
					t.Fatal(err.Error())
				}

				w, err = NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				var output testObj
				err = w.Read("uniqueid", &output)
				if err != nil {
					t.Fatal(err.Error())
				}
				if output != input {
					t.Fatalf("Expected: %s, Actual: %s", input, output)
				}
			})

			db.Teardown()

			t.Run("TestUpdateItemInWallet", func(t *testing.T) {
				s := db.Setup()
				w, err := NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				input := testObj{A: "b"}
				err = w.Create("uniqueid", input)
				if err != nil {
					t.Fatal(err.Error())
				}

				err = w.Read("uniqueid", &input)
				if err != nil {
					t.Fatal(err.Error())
				}

				input.A = "c"
				err = w.Update("uniqueid", input)
				if err != nil {
					t.Fatal(err.Error())
				}

				var output testObj
				err = w.Read("uniqueid", &output)
				if err != nil {
					t.Fatal(err.Error())
				}
				if output != input {
					t.Fatalf("Expected: %s, Actual: %s", input, output)
				}
			})

			db.Teardown()

			t.Run("TestDeleteItemInWallet", func(t *testing.T) {
				s := db.Setup()
				w, err := NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				input := testObj{A: "b"}
				err = w.Create("uniqueid", input)
				if err != nil {
					t.Fatal(err.Error())
				}

				err = w.Delete("uniqueid")
				if err != nil {
					t.Fatal(err.Error())
				}

				var output testObj
				err = w.Read("uniqueid", &output)
				if err != ErrorNotFound {
					t.Fatalf("Expected: %s, Actual: %s", ErrorNotFound, err)
				}
			})

			db.Teardown()

			t.Run("TestCreateKey", func(t *testing.T) {
				s := db.Setup()
				w, err := NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				kid, err := w.CreateKey(Ed25519VerificationKey2018Type)
				if err != nil {
					t.Fatal(err.Error())
				}

				o := testObj{A: "b"}
				b, err := json.Marshal(o)
				if err != nil {
					t.Fatal(err.Error())
				}
				sig, err := w.Sign(kid, b)
				if err != nil {
					t.Fatal(err.Error())
				}

				res := w.Verify(kid, b, sig)
				if !res {
					t.Fatalf("Signature did not validate")
				}
			})

			db.Teardown()

			t.Run("TestCannotExtractKey", func(t *testing.T) {
				s := db.Setup()
				w, err := NewWallet("supersecret", s)
				if err != nil {
					t.Fatal(err.Error())
				}

				kid, err := w.CreateKey(Ed25519VerificationKey2018Type)
				if err != nil {
					t.Fatal(err.Error())
				}

				var key ed25519.PrivateKey
				err = w.Read(kid, &key)
				if err == nil {
					t.Fatal("Expected an error, got nil.")
				}
			})

			db.Teardown()
		})
	}
}
