package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/valkey-io/valkey-go"
	"github.com/Vasu1712/dragon-auth/internal/config"
	"github.com/Vasu1712/dragon-auth/internal/handlers"
)

// SetupRouter configures and returns the application router
func SetupRouter(client valkey.Client, config *config.Config) *mux.Router {
	router := mux.NewRouter()
	
	// Create auth handler
	authHandler := handlers.NewAuthHandler(client, config)
	
	// Public routes
	router.HandleFunc("/api/auth/register", authHandler.Register).Methods("POST")
	router.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")
	
	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")
	
	// Protected routes
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(handlers.AuthMiddleware(client, config))
	
	protected.HandleFunc("/auth/logout", authHandler.Logout).Methods("POST")
	protected.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		// Simple handler to return the authenticated user
		user := r.Context().Value("user")
		w.Header().Set("Content-Type", "application/json")
		http.ServeJSON(w, user)
	}).Methods("GET")
	
	return router
}
