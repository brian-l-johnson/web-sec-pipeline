//go:generate swag init -g cmd/server/main.go --output docs

// @title           Web Security Pipeline — Coordinator API
// @version         1.0
// @description     Tracks web scan jobs and serves findings.
// @host            web-coordinator.apps.blj.wtf
// @BasePath        /

package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/api"
	_ "github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/docs"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/jobs"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/pipeline"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/queue"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

//go:embed ui
var uiFiles embed.FS

func main() {
	natsURL       := getEnv("NATS_URL", "nats://localhost:4222")
	databaseURL   := mustEnv("DATABASE_URL")
	crawlerImage  := getEnv("CRAWLER_IMAGE", "ghcr.io/brian-l-johnson/web-crawler:latest")
	zapImage      := getEnv("ZAP_IMAGE", "ghcr.io/brian-l-johnson/zap-runner:latest")
	nucleiImage   := getEnv("NUCLEI_IMAGE", "ghcr.io/brian-l-johnson/nuclei-runner:latest")
	servicePort   := getEnv("SERVICE_PORT", "8080")
	dataDir       := getEnv("DATA_DIR", "/data")
	migrationsDir := getEnv("GOOSE_MIGRATION_DIR", "/migrations")
	k8sNamespace  := getEnv("NAMESPACE", "web-sec-tools")
	k8sPVCName    := getEnv("PVC_NAME", "web-sec-tools-data")

	// Run Goose migrations before connecting anything else.
	log.Println("running database migrations...")
	if err := runMigrations(databaseURL, migrationsDir); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}
	log.Println("migrations complete")

	s, err := store.New(databaseURL)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	defer s.Close()

	manager, err := jobs.NewManager(crawlerImage, zapImage, nucleiImage, k8sNamespace, k8sPVCName)
	if err != nil {
		log.Fatalf("create k8s job manager: %v", err)
	}

	orch := pipeline.NewOrchestrator(s, manager, dataDir)

	// Reconcile jobs that were running when the coordinator last died.
	log.Println("reconciling running jobs...")
	bgCtx := context.Background()
	runningJobs, err := s.ListRunningJobs(bgCtx)
	if err != nil {
		log.Printf("warn: list running jobs: %v", err)
	} else if len(runningJobs) > 0 {
		ids := make([]uuid.UUID, len(runningJobs))
		for i, j := range runningJobs {
			ids[i] = j.ID
		}
		if err := manager.ReconcileRunningJobs(bgCtx, ids, orch); err != nil {
			log.Printf("warn: reconcile running jobs: %v", err)
		}
	}
	log.Println("reconciliation complete")

	// Mark jobs that have been stuck in 'running' for more than 4 hours as
	// failed. This handles the case where all k8s Jobs TTL-expired before the
	// coordinator restarted and reconcile had nothing to process.
	log.Println("sweeping stale jobs...")
	orch.SweepStaleJobs(bgCtx)
	log.Println("stale job sweep complete")

	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	go func() {
		log.Println("starting k8s job watcher...")
		manager.WatchJobs(workerCtx, orch)
	}()

	consumer, err := queue.NewConsumer(natsURL, orch)
	if err != nil {
		log.Fatalf("create nats consumer: %v", err)
	}
	defer consumer.Close()

	go func() {
		log.Println("starting nats consumer...")
		if err := consumer.Run(workerCtx); err != nil && workerCtx.Err() == nil {
			log.Printf("nats consumer exited: %v", err)
		}
	}()

	h := api.NewHandler(s, orch, orch, orch, manager, dataDir)
	h.AddHealthCheck(s.Ping)
	h.AddHealthCheck(func(ctx context.Context) error {
		if !consumer.Healthy() {
			return fmt.Errorf("NATS disconnected")
		}
		return nil
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.Handle("GET /swagger/", httpSwagger.WrapHandler)

	// Serve the embedded web UI at /ui/.
	uiSub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		log.Fatalf("embed ui sub: %v", err) // should never happen with valid embed path
	}
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(uiSub))))

	// Root redirects to the web UI.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	addr := fmt.Sprintf(":%s", servicePort)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("web-coordinator listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down...")
	workerCancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http server shutdown error: %v", err)
	}
	log.Println("shutdown complete")
}

func runMigrations(databaseURL, migrationsDir string) error {
	connConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse database URL: %w", err)
	}
	db := stdlib.OpenDB(*connConfig)
	defer db.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, migrationsDir); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}
