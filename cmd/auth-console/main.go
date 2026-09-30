// Command auth-console is the identity console of a Yundera PCS or a FOSS mesh
// box: the local (Authelia) accounts, and who can reach the host over SSH. It
// ships in the auth stack beside Dex and Authelia, sits behind an AppShield
// gate and serves an embedded Svelte UI plus a small JSON API.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yundera/auth-console/internal/config"
	"github.com/yundera/auth-console/internal/server"
	"github.com/yundera/auth-console/internal/ui"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("auth-console: ")

	cfg := config.FromEnv()
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           server.New(cfg, ui.Dist()),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("v%s listening on %s (host root %s, mounted at %s)", server.Version, cfg.Addr, cfg.HostRoot, cfg.HostRootMount)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
