package cmd

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func NewProfileHttpServer(addr string) {
	go func() {
		log.Fatalln(http.ListenAndServe(addr, nil))
	}()
}
