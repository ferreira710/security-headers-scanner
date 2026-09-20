// Command server runs the scanner as a long-lived HTTP service: what the
// Compose setup and anyone self-hosting the container use. The Netlify deploy
// runs the same handler through a Lambda adapter instead.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ferreira710/security-headers-scanner/backend/internal/api"
	"github.com/ferreira710/security-headers-scanner/backend/internal/config"
)

const pruneInterval = 5 * time.Minute

// health is the container HEALTHCHECK. The final image is FROM scratch, so
// there is no curl and no shell to call one: the binary checks itself.
func health(port string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/api/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "health respondeu %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

func main() {
	checkHealth := flag.Bool("health", false, "consulta /api/health no proprio processo e sai")
	flag.Parse()

	settings := config.FromEnv()
	if *checkHealth {
		os.Exit(health(settings.Port))
	}
	server := api.NewServer(settings)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server.StartPruning(ctx, pruneInterval)

	httpServer := &http.Server{
		Addr:    ":" + settings.Port,
		Handler: server.Handler(),
		// The scan itself is bounded by SCAN_TOTAL_TIMEOUT; these bound a
		// client that is slow on purpose.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      settings.TotalTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("scanner ouvindo em :%s", settings.Port)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("servidor parou: %v", err)
	}
}
