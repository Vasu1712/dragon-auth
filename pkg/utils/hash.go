package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id Params (OWASP Recommendations)
	memory      = 64 * 1024 // 64 MB
	iterations  = 1
	parallelism = 4
	saltLength  = 16
	keyLength   = 32
)

// HashPassword generates an Argon2id hash using a password, a random salt, and a secret pepper
func HashPassword(password, pepper string) (string, error) {
	// 1. Generate a random salt
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// 2. Combine Password + Pepper
	input := []byte(password + pepper)

	// 3. Generate Hash using Argon2id
	hash := argon2.IDKey(input, salt, iterations, memory, parallelism, keyLength)

	// 4. Encode as Base64 string to store in DB
	// Format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// CheckPasswordHash compares a plain password+pepper against the stored hash
func CheckPasswordHash(password, pepper, encodedHash string) (bool, error) {
	// 1. Parse the encoded hash string
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	// parts[0] is empty, parts[1] is "argon2id", parts[2] is version, parts[3] is params
	// parts[4] is salt, parts[5] is hash

	if parts[1] != "argon2id" {
		return false, errors.New("incompatible hash type")
	}

	var mem, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads)
	if err != nil {
		return false, errors.New("invalid hash parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}

	// 2. Combine provided Password + Pepper
	input := []byte(password + pepper)

	// 3. Hash the input using the extracted salt and params
	paramsHash := argon2.IDKey(input, salt, time, mem, threads, uint32(len(decodedHash)))

	// 4. Compare using ConstantTimeCompare (prevents timing attacks)
	if subtle.ConstantTimeCompare(decodedHash, paramsHash) == 1 {
		return true, nil
	}
	return false, nil
}