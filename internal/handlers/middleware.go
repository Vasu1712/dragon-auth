package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/Vasu1712/dragon-auth/internal/config"
	"github.com/Vasu1712/dragon-auth/internal/models"
	"github.com/Vasu1712/dragon-auth/pkg/utils"
	"github.com/valkey-io/valkey-go"
)

// AuthMiddleware validates JWT tokens and adds user info to request context
func AuthMiddleware(client valkey.Client, config *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.Background()
			tenantID := r.Context().Value("tenant_id").(string)

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
			tokenKey := utils.TokenKey(tenantID, tokenString)
			userID, err := client.Do(ctx, client.B().Get().Key(tokenKey).Build()).ToString()
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Get user email from ID
			userIDKey := utils.UserIDKey(tenantID, userID)
			email, err := client.Do(ctx, client.B().Get().Key(userIDKey).Build()).ToString()
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Get user data
			userKey := utils.UserKey(tenantID, email)
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
            
            // Create a middleware that checks for admin role or superadmin email
            checkAdmin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                // Get user from context (set by auth middleware)
                user, ok := r.Context().Value("user").(models.User)
                
                // Check if user is superadmin by email
                isSuperAdmin := user.Email == "vasupal.17.12.2002@gmail.com"
                
                // Allow if user is admin or superadmin
                if !ok || (user.Role != "admin" && !isSuperAdmin) {
                    http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
                    return
                }
                
                // Add superadmin flag to context
                ctx := context.WithValue(r.Context(), "is_superadmin", isSuperAdmin)

				tenantID := r.Context().Value("tenant_id").(string)
                if isSuperAdmin && tenantID == "all" {
                    // Mark context to fetch all tenants
                    ctx = context.WithValue(ctx, "fetch_all_tenants", true)
                    log.Println("Superadmin mode activated, fetching all tenants")
                }
                
                // User is an admin or superadmin, proceed
                next.ServeHTTP(w, r.WithContext(ctx))
            })
            
            // Apply both middlewares
            authMiddleware(checkAdmin).ServeHTTP(w, r)
        })
    }
}


func TenantMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tenantID := r.Header.Get("X-Tenant-ID")
        if tenantID == "" {
            http.Error(w, "Tenant ID required", http.StatusBadRequest)
            return
        }

        // Validate tenant exists (you'd query your tenant storage here)
        // For simplicity, we'll assume validation happens elsewhere
        ctx := context.WithValue(r.Context(), "tenant_id", tenantID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
