package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Vasu1712/dragon-auth/internal/config"
	"github.com/Vasu1712/dragon-auth/internal/models"
	"github.com/Vasu1712/dragon-auth/pkg/utils"
	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go"
)

// AuthHandler handles authentication-related endpoints
type AuthHandler struct {
	client valkey.Client
	config *config.Config
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(client valkey.Client, config *config.Config) *AuthHandler {
	return &AuthHandler{
		client: client,
		config: config,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var req models.RegisterRequest

	tenantID, ok := r.Context().Value("tenant_id").(string)
    if !ok || tenantID == "" {
        http.Error(w, "Invalid tenant context", http.StatusBadRequest)
        return
    }

	// Parse request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	userKey := utils.UserKey(tenantID, req.Email)
	exists, err := h.client.Do(ctx, h.client.B().Exists().Key(userKey).Build()).AsInt64()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "Email already registered", http.StatusConflict)
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Error processing request", http.StatusInternalServerError)
		return
	}

	// Create user
	userID := uuid.New().String()
	now := time.Now().UTC()

	user := models.User{
		ID:           userID,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         "user",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Store user data
	userJSON, _ := json.Marshal(user)
	err = h.client.Do(ctx, h.client.B().Set().Key(userKey).Value(string(userJSON)).Build()).Error()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Create mapping from ID to email for lookup
	userIDKey := utils.UserIDKey(tenantID, userID)
	err = h.client.Do(ctx, h.client.B().Set().Key(userIDKey).Value(req.Email).Build()).Error()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	token, expiry, err := utils.GenerateJWT(user, h.config.JWTSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Store token in Valkey with TTL
	tokenKey := utils.TokenKey(tenantID, token)
	expirySeconds := int64(expiry.Sub(now).Seconds())
	err = h.client.Do(ctx, h.client.B().Set().Key(tokenKey).Value(user.ID).
		Ex(time.Duration(expirySeconds) * time.Second).Build()).Error()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	userResponse := models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	
	response := models.AuthResponse{
		Token:   token,
		Expires: expiry.Format(time.RFC3339),
		User:    userResponse,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value("tenant_id").(string)
	ctx := context.Background()
	var req models.LoginRequest

	// Parse request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !ok || tenantID == "" {
        http.Error(w, "Invalid tenant context", http.StatusBadRequest)
        return
    }

	// Validate input
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Get user data
	userKey := utils.UserKey(tenantID, req.Email)
	userJSON, err := h.client.Do(ctx, h.client.B().Get().Key(userKey).Build()).ToString()
	if err != nil {
		http.Error(w, "Invalid credentials: Error in getting user data", http.StatusUnauthorized)
		return
	}

	// Parse user data
	var user models.User
	if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

		// After getting user data
		log.Printf("User lookup for %s: success=%v", req.Email, userJSON != "")

		// During password verification
		log.Printf("Password verification for %s: %v", req.Email,
			utils.CheckPasswordHash(req.Password, user.PasswordHash))

	// Verify password
	if !utils.CheckPasswordHash(req.Password, user.PasswordHash) {
		http.Error(w, "Invalid credentials: Error in verifying password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, expiry, err := utils.GenerateJWT(user, h.config.JWTSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Store token in Valkey with TTL
	now := time.Now().UTC()
	tokenKey := utils.TokenKey(tenantID, token)
	expirySeconds := int64(expiry.Sub(now).Seconds())
	err = h.client.Do(ctx, h.client.B().Set().Key(tokenKey).Value(user.ID).
		Ex(time.Duration(expirySeconds) * time.Second).Build()).Error()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	userResponse := models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	
	response := models.AuthResponse{
		Token:   token,
		Expires: expiry.Format(time.RFC3339),
		User:    userResponse,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	tokenString := r.Header.Get("Authorization")
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// Delete token from Valkey
	tokenKey := "token:" + tokenString
	err := h.client.Do(ctx, h.client.B().Del().Key(tokenKey).Build()).Error()
	if err != nil {
		http.Error(w, "Error logging out", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
