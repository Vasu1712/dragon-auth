package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	Port        string
	ValkeyURI   string
	JWTSecret   string
	Environment string
	DefaultTenantID string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	godotenv.Load()

	config := &Config{
		Port:        getEnv("PORT", "9090"),
		ValkeyURI:   os.Getenv("VALKEY_URI"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		Environment: getEnv("ENVIRONMENT", "development"),
		DefaultTenantID: getEnv("DEFAULT_TENANT_ID", "default"),
	}

	// Validate required fields
	if config.ValkeyURI == "" {
		return nil, errors.New("VALKEY_URI environment variable is required")
	}

	if config.JWTSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable is required")
	}

	return config, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
