package chain

import (
	"crypto/rand"
	"fmt"
)

// // // // Helper function to generate a random salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, 32) // Using 32 bytes for salt
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}
