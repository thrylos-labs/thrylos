package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateAESKey generates a new AES-256 symmetric key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	key, err := GenerateAESKey()
	if err != nil {
		fmt.Println("Error generating AES key:", err)
		return
	}

	// Encode the key in base64 so it can be safely displayed and stored
	encodedKey := base64.StdEncoding.EncodeToString(key)
	fmt.Println(encodedKey)
}
