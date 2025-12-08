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

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Project == "" {
		http.Error(w, "Email, password and project are required", http.StatusBadRequest)
		return
	}

	project := req.Project

	userKey := utils.UserKey(project, req.Email)
	exists, err := h.client.Do(ctx, h.client.B().Exists().Key(userKey).Build()).AsInt64()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "Email already registered", http.StatusConflict)
		return
	}

	projectUserPattern := project + ":user:*"

	existingUsers, err := h.client.Do(ctx, h.client.B().Keys().Pattern(projectUserPattern).Build()).AsStrSlice()
	if err != nil {
		http.Error(w, "Database error checking project status", http.StatusInternalServerError)
		return
	}

	role := "user"

	if len(existingUsers) == 0 {
		role = "admin"
	}

	if h.config.SuperAdminEmail != "" && req.Email == h.config.SuperAdminEmail {
		role = "superadmin"
	}

	hashedPassword, err := utils.HashPassword(req.Password, h.config.PasswordPepper)
	if err != nil {
		http.Error(w, "Error processing request", http.StatusInternalServerError)
		return
	}

	userID := uuid.New().String()
	now := time.Now().UTC()

	user := models.User{
		ID:           userID,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         role,
		Project:      project,
		CreatedAt:    now,
		UpdatedAt:    now,
		PhoneNumber:  req.PhoneNumber,
	}

	userJSON, _ := json.Marshal(user)
	err = h.client.Do(ctx, h.client.B().Set().Key(userKey).Value(string(userJSON)).Build()).Error()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	userIDKey := utils.UserIDKey(project, userID)
	h.client.Do(ctx, h.client.B().Set().Key(userIDKey).Value(req.Email).Build())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"user": models.UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			Role:      user.Role,
			Project:   user.Project,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
	})
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var req models.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Decode error: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Project == "" {
		http.Error(w, "Email, password and project are required", http.StatusBadRequest)
		return
	}

	project := req.Project

	userKey := utils.UserKey(project, req.Email)

	userJSON, err := h.client.Do(ctx, h.client.B().Get().Key(userKey).Build()).ToString()
	if err != nil {
		log.Printf("User lookup failed for %s@%s: %v", req.Email, project, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var user models.User
	if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	log.Printf("User lookup for %s: success=%v", req.Email, userJSON != "")

	ok, err := utils.CheckPasswordHash(req.Password, h.config.PasswordPepper, user.PasswordHash)
	if err != nil {
		log.Printf("Password verification error for %s: %v", req.Email, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if !ok {
		http.Error(w, "Invalid credentials: Error in verifying password", http.StatusUnauthorized)
		return
	}

	token, expiry, err := utils.GenerateJWT(user, h.config.JWTSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	tokenKey := utils.TokenKey(project, token)
	expirySeconds := int64(expiry.Sub(now).Seconds())

	err = h.client.Do(ctx, h.client.B().Set().Key(tokenKey).Value(user.ID).
		Ex(time.Duration(expirySeconds)*time.Second).Build()).Error()
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
		Project:   user.Project,
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