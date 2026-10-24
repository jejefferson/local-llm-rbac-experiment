// Command rbac starts the in-memory, multi-tenant RBAC HTTP API.
//
// Startup (documented contract):
//
//	go run . -addr :8080
//
// Flags:
//
//	-addr string  host:port to listen on (default ":8080")
//	-seed  bool   load the public fixtures (default true)
//
// All endpoints live under /api/v1/. Authentication is an opaque bearer token
// in the "Authorization: Bearer <token>" header; the token's tenant and the
// caller's role are resolved server-side. See README.md for the full contract.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rbac/internal/rbac"
)

func main() {
	addr := flag.String("addr", ":8080", "host:port to listen on (e.g. -addr :8080)")
	seed := flag.Bool("seed", true, "load the public fixtures on startup")
	flag.Parse()

	store := rbac.NewStore()
	if *seed {
		if err := rbac.SeedAll(store); err != nil {
			log.Printf("warning: seeding failed: %v", err)
		} else {
			rbac.LogFixtures(store)
		}
	}

	srv := rbac.NewServer(store)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Keep the body small and bound; the store is the only state.
		IdleTimeout: 30 * time.Second,
	}

	// Start the server.
	lnErrCh := make(chan error, 1)
	go func() {
		log.Printf("rbac listening on %s", *addr)
		lnErrCh <- httpServer.ListenAndServe()
	}()

	// Graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-lnErrCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	case <-ctx.Done():
		log.Print("shutting down...")
	}

	// Give in-flight requests a moment to finish.
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutCtx)
}
