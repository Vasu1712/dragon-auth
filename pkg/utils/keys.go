package utils

import "github.com/google/uuid"

func UserKey(project, email string) string {
    return project + ":user:" + email
}

func TokenKey(project, token string) string {
    return project + ":token:" + token
}

func UserIDKey(project, userID string) string {
    return project + ":userid:" + userID
}

func GenerateAPIKey() string {
    return uuid.New().String()
}

