package main

import (
	"flag"
	"log"

	"rbac/internal/api"
	"rbac/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	flag.Parse()

	st := store.New()
	srv := api.NewServer(st)

	log.Printf("rbac service starting on %s", *addr)
	if err := srv.ListenAndServe(*addr); err != nil {
		log.Fatal(err)
	}
}
