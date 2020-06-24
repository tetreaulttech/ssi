package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type body struct {
}

func handler(rw http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var b body
	err := decoder.Decode(&b)
	if err != nil {
		log.Println(err)
	}

	j, _ := json.MarshalIndent(mux.Vars(r), "", "  ")
	log.Printf("Method: %s", r.Method)
	log.Printf("URL: %s", r.URL.String())
	log.Printf("Params: %s", string(j))
	s, _ := json.MarshalIndent(b, "", "  ")
	log.Println(string(s))

	params := mux.Vars(r)

	switch params["topic"] {
	case "status":
		return // 200
	}
}
