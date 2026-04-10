//go:generate swag init -g cmd/server/main.go --output docs

// @title           Web Security Pipeline — Ingestion API
// @version         1.0
// @description     Accepts web scan submission requests and queues them for analysis.
// @host            web-ingestion.apps.blj.wtf
// @BasePath        /

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-ingestion/internal/api"
	_ "github.com/brian-l-johnson/web-sec-pipeline/services/web-ingestion/docs"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-ingestion/internal/queue"
)

func getenv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	servicePort := getenv("SERVICE_PORT", "8080")

	pub, err := queue.NewPublisher(natsURL)
	if err != nil {
		slog.Error("connecting to NATS", "url", natsURL, "err", err)
		os.Exit(1)
	}
	defer pub.Close()

	h := api.NewHandler(pub)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan", h.ScanHandler)
	mux.HandleFunc("GET /health", h.HealthHandler)
	mux.Handle("/swagger/", httpSwagger.WrapHandler)

	srv := &http.Server{
		Addr:         ":" + servicePort,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("web-ingestion service starting", "port", servicePort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	slog.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
}
