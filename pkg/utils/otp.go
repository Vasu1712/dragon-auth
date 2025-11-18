package utils

import (
    "crypto/rand"
    "fmt"
    "math/big"
    "time"
)

// GenerateOTP generates a random 6-digit OTP
func GenerateOTP() (string, error) {
    max := big.NewInt(1000000)
    n, err := rand.Int(rand.Reader, max)
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("%06d", n), nil
}

// OTPKey returns the key used to store OTPs in the database
func OTPKey(tenantID, phoneNumber string) string {
    return fmt.Sprintf("%s:otp:%s", tenantID, phoneNumber)
}

// OTPExpiry returns the expiry time for OTPs (5 minutes)
func OTPExpiry() time.Duration {
    return 5 * time.Minute
}