package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/valkey-io/valkey-go"
	"github.com/Vasu1712/dragon-auth/internal/config"
	"github.com/Vasu1712/dragon-auth/internal/models"
	"github.com/Vasu1712/dragon-auth/pkg/utils"
)

// AuthMiddleware validates JWT tokens and adds user info to request context
func AuthMiddleware(client valkey.Client, config *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.Background()

			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Check if authorization header has the right format
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}

			// Extract token
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Validate token format
			claims, err := utils.ValidateJWT(tokenString, config.JWTSecret)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Check if token is in Valkey
			tokenKey := "token:" + tokenString
			userID, err := client.Do(ctx, client.B().Get().Key(tokenKey).Build()).ToString()
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Get user email from ID
			email, err := client.Do(ctx, client.B().Get().Key("userid:"+userID).Build()).ToString()
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Get user data
			userKey := "user:" + email
			userJSON, err := client.Do(ctx, client.B().Get().Key(userKey).Build()).ToString()
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Parse user data
			var user models.User
			if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
				http.Error(w, "Error processing user data", http.StatusInternalServerError)
				return
			}

			// Add user to request context
			ctx = context.WithValue(r.Context(), "user", user)
			ctx = context.WithValue(ctx, "claims", claims)

			// Call next handler with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AdminMiddleware(client valkey.Client, config *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First apply the regular auth middleware
			authMiddleware := AuthMiddleware(client, config)
			
			// Create a middleware that checks for admin role
			checkAdmin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Get user from context (set by auth middleware)
				user, ok := r.Context().Value("user").(models.User)
				if !ok || user.Role != "admin" {
					http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
					return
				}
				
				// User is an admin, proceed
				next.ServeHTTP(w, r)
			})
			
			// Apply both middlewares
			authMiddleware(checkAdmin).ServeHTTP(w, r)
		})
	}
}