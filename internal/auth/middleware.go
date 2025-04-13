package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func AuthMiddleware(rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate JWT
		claims, err := ValidateJWT(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Check Redis for token validity
		ctx := context.Background()
		exists, err := rdb.Exists(ctx, "user:"+claims.Subject+":tokens").Result()
		if err != nil || exists == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			return
		}

		// Set user context
		c.Set("userID", claims.Subject)
		c.Next()
	}
}
