package main

import (
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/agent/command/{topic}/", handler).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc(" /agent/command/{topic}/id", handler).Methods(http.MethodGet)

	srv := &http.Server{
		Addr: "0.0.0.0:" + os.Getenv("PORT"),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	http.Handle("/", r)

	log.Fatal(srv.ListenAndServe())
}
