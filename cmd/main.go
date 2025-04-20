package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Vasu1712/dragon-auth/internal/config"
	"github.com/Vasu1712/dragon-auth/internal/database"
	"github.com/Vasu1712/dragon-auth/internal/routes"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Valkey client
	client, err := database.NewValkeyClient(cfg.ValkeyURI)
	if err != nil {
		log.Fatalf("Failed to connect to Valkey: %v", err)
	}
	defer client.Close()

	// Test connection
	ctx := context.Background()
	err = client.Do(ctx, client.B().Ping().Build()).Error()
	if err != nil {
		log.Fatalf("Failed to ping Valkey: %v", err)
	}
	log.Println("Successfully connected to Valkey")

	// Set up router
	router := routes.SetupRouter(client, cfg)

	// Configure server
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server running on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
	log.Println("Server stopped gracefully")
}
