package handlers

import (
	"context"
	"encoding/json"
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

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := utils.ValidateJWT(tokenString, config.JWTSecret)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Use Subject from claims as project/tenant identifier
			project := claims.Project
			
			if project == "" {
				http.Error(w, "Invalid token: project missing", http.StatusUnauthorized)
				return
			}

			tokenKey := utils.TokenKey(project, tokenString)
			userID, err := client.Do(ctx, client.B().Get().Key(tokenKey).Build()).ToString()
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			userIDKey := utils.UserIDKey(project, userID)
			email, err := client.Do(ctx, client.B().Get().Key(userIDKey).Build()).ToString()
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			userKey := utils.UserKey(project, email)
			userJSON, err := client.Do(ctx, client.B().Get().Key(userKey).Build()).ToString()
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			var user models.User
			if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
				http.Error(w, "Error processing user data", http.StatusInternalServerError)
				return
			}

			ctxWithUser := context.WithValue(r.Context(), "user", user)
			ctxWithUser = context.WithValue(ctxWithUser, "claims", claims)
			next.ServeHTTP(w, r.WithContext(ctxWithUser))
		})
	}
}

func AdminMiddleware(client valkey.Client, config *config.Config) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        // Define the admin check logic
        adminCheck := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Now this runs AFTER AuthMiddleware, so "user" is present
            user, ok := r.Context().Value("user").(models.User)
            if !ok {
                http.Error(w, "Unauthorized: User context missing", http.StatusUnauthorized)
                return
            }

            isSuperAdmin := false
            if config.SuperAdminEmail != "" && user.Email == config.SuperAdminEmail {
                isSuperAdmin = true
            }

            if user.Role != "admin" && !isSuperAdmin {
                http.Error(w, "Unauthorized: Admin access required", http.StatusForbidden)
                return
            }

            ctx := context.WithValue(r.Context(), "is_superadmin", isSuperAdmin)
            next.ServeHTTP(w, r.WithContext(ctx))
        })

        // Wrap the admin check with AuthMiddleware
        // Flow: Request -> AuthMiddleware -> AdminCheck -> Next (Your Handler)
        return AuthMiddleware(client, config)(adminCheck)
    }
}

