package main

import (
	"log"
	"os"
	
	"github.com/vasu1712/dragonAuth/internal/auth"
	"github.com/vasu1712/dragonAuth/internal/storage"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize Redis/DragonflyDB connection
	rdb := storage.NewRedisClient(
		os.Getenv("DRAGONFLY_PASSWORD"),
		os.Getenv("DRAGONFLY_HOST"),
	)

	// Create Gin router with middleware
	r := gin.Default()
	r.Use(auth.AuthMiddleware(rdb))

	// Register routes
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/login", auth.LoginHandler)
		authGroup.POST("/refresh", auth.RefreshHandler)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(r.Run(":" + port))
}