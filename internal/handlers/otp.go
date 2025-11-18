// internal/handlers/otp.go
package handlers

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

    "github.com/Vasu1712/dragon-auth/internal/config"
    "github.com/Vasu1712/dragon-auth/internal/models"
    "github.com/Vasu1712/dragon-auth/pkg/utils"
    "github.com/Vasu1712/dragon-auth/pkg/whatsapp"
    "github.com/valkey-io/valkey-go"
)

type OTPHandler struct {
    client          valkey.Client
    config          *config.Config
    whatsappClient  *whatsapp.Client
}

func NewOTPHandler(client valkey.Client, config *config.Config, whatsappClient *whatsapp.Client) *OTPHandler {
    return &OTPHandler{
        client:         client,
        config:         config,
        whatsappClient: whatsappClient,
    }
}

// RequestOTP handles sending OTP via WhatsApp
func (h *OTPHandler) RequestOTP(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    tenantID := r.Context().Value("tenant_id").(string)
    
    var req models.OTPRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Validate phone number
    if req.PhoneNumber == "" {
        http.Error(w, "Phone number is required", http.StatusBadRequest)
        return
    }
    
    // Generate OTP
    otp, err := utils.GenerateOTP()
    if err != nil {
        http.Error(w, "Error generating OTP", http.StatusInternalServerError)
        return
    }
    
    // Store OTP in Valkey with expiry
    otpKey := utils.OTPKey(tenantID, req.PhoneNumber)
    expiry := utils.OTPExpiry()
    err = h.client.Do(ctx, h.client.B().Set().Key(otpKey).Value(otp).
        Ex(expiry).Build()).Error()
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    
    // Send OTP via WhatsApp
    err = h.whatsappClient.SendOTP(req.PhoneNumber, otp)
    if err != nil {
        http.Error(w, "Failed to send OTP", http.StatusInternalServerError)
        return
    }
    
    // Return success response
    expireAt := time.Now().Add(expiry)
    response := models.OTPResponse{
        Success:  true,
        Message:  "OTP sent successfully",
        ExpireAt: expireAt.Format(time.RFC3339),
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// VerifyOTP handles OTP verification and user login
func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()
    tenantID := r.Context().Value("tenant_id").(string)
    
    var req models.OTPVerifyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Validate input
    if req.PhoneNumber == "" || req.OTP == "" {
        http.Error(w, "Phone number and OTP are required", http.StatusBadRequest)
        return
    }
    
    // Get stored OTP
    otpKey := utils.OTPKey(tenantID, req.PhoneNumber)
    storedOTP, err := h.client.Do(ctx, h.client.B().Get().Key(otpKey).Build()).ToString()
    if err != nil {
        http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
        return
    }
    
    // Verify OTP
    if storedOTP != req.OTP {
        http.Error(w, "Invalid OTP", http.StatusUnauthorized)
        return
    }
    
    // Delete the OTP (one-time use)
    h.client.Do(ctx, h.client.B().Del().Key(otpKey).Build())
    
    // Find user by phone number
    var user models.User
    userFound := false
    
    // Get all users and find one with matching phone
    userKeys, _ := h.client.Do(ctx, h.client.B().Keys().Pattern(tenantID+":user:*").Build()).AsStrSlice()
    for _, key := range userKeys {
        userJSON, err := h.client.Do(ctx, h.client.B().Get().Key(key).Build()).ToString()
        if err != nil {
            continue
        }
        
        var u models.User
        if err := json.Unmarshal([]byte(userJSON), &u); err != nil {
            continue
        }
        
        if u.PhoneNumber == req.PhoneNumber {
            user = u
            userFound = true
            break
        }
    }
    
    if !userFound {
        http.Error(w, "No user found with this phone number", http.StatusUnauthorized)
        return
    }
    
    // Generate JWT token
    token, expiry, err := utils.GenerateJWT(user, h.config.JWTSecret)
    if err != nil {
        http.Error(w, "Error generating token", http.StatusInternalServerError)
        return
    }
    
    // Store token in database
    tokenKey := utils.TokenKey(tenantID, token)
    expirySeconds := int64(expiry.Sub(time.Now()).Seconds())
    h.client.Do(ctx, h.client.B().Set().Key(tokenKey).Value(user.ID).
        Ex(time.Duration(expirySeconds) * time.Second).Build())
    
    // Create response
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
