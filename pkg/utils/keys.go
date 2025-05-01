package utils

import "github.com/google/uuid"

func UserKey(tenantID, email string) string {
    return tenantID + ":user:" + email
}

func TokenKey(tenantID, token string) string {
    return tenantID + ":token:" + token
}

func UserIDKey(tenantID, userID string) string {
    return tenantID + ":userid:" + userID
}

func GenerateAPIKey() string {
    return uuid.New().String()
}

