package database

import (
	"github.com/valkey-io/valkey-go"
)

// NewValkeyClient creates a new Valkey client with the provided URI
func NewValkeyClient(uri string) (valkey.Client, error) {
	// Create client options
	options := valkey.ClientOption{
		// NOTE: We're NOT using the full URI here, we need to parse it
		// and extract the host and port
		
		// For secure connections (rediss://), we need to specify TLS
		// If your URI starts with "rediss://", enable TLS
		TLSEnable: true, 
	}

	// Extract credentials and host:port from URI
	// This is a simplified approach - a real implementation might use a URI parser
	
	// For Aiven, the format is usually: rediss://default:PASSWORD@host:port
	// We need to extract host:port for the InitAddress field
	
	// Example implementation (a real one would need proper URI parsing)
	// Note: This is purposely simplistic for the example
	
	// Extract host:port from URI (removing protocol and auth)
	hostPort := extractHostPort(uri)
	
	// Set the host:port in the options
	options.InitAddress = []string{hostPort}
	
	// If authentication is needed (which it is for Aiven)
	options.Username, options.Password = extractCredentials(uri)

	// Create and return the client
	return valkey.NewClient(options)
}

// extractHostPort extracts the host:port from a Redis URI
// This is a simplified implementation - a real one would use proper URI parsing
func extractHostPort(uri string) string {
	// For example: rediss://default:password@valkey-dragon-auth.j.aivencloud.com:21463
	// Should return: valkey-dragon-auth.j.aivencloud.com:21463
	
	// Find position of @ character (which separates auth from host)
	atPos := -1
	for i, char := range uri {
		if char == '@' {
			atPos = i
			break
		}
	}
	
	if atPos == -1 {
		// If no @ is found, assume the URI is already in host:port format
		return uri
	}
	
	// Return everything after the @ character
	return uri[atPos+1:]
}

// extractCredentials extracts the username and password from a Redis URI
func extractCredentials(uri string) (string, string) {
	// For example: rediss://default:password@valkey-dragon-auth.j.aivencloud.com:21463
	// Should return: "default", "password"
	
	// This is a simplistic implementation
	// Find position of // (protocol separator)
	protoPos := -1
	for i := 0; i < len(uri)-1; i++ {
		if uri[i] == '/' && uri[i+1] == '/' {
			protoPos = i + 1
			break
		}
	}
	
	if protoPos == -1 {
		return "", ""
	}
	
	// Find position of @ character
	atPos := -1
	for i, char := range uri {
		if char == '@' {
			atPos = i
			break
		}
	}
	
	if atPos == -1 {
		return "", ""
	}
	
	// Extract auth part (between // and @)
	authPart := uri[protoPos+1:atPos]
	
	// Find position of : in auth part
	colonPos := -1
	for i, char := range authPart {
		if char == ':' {
			colonPos = i
			break
		}
	}
	
	if colonPos == -1 {
		return authPart, ""
	}
	
	// Return username and password
	return authPart[:colonPos], authPart[colonPos+1:]
}
