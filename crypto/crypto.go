package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const (
	keyLen    = 32 // AES-256
	nonceSize = 12
	saltSize  = 32
)

var ErrInvalidKeySize = errors.New("invalid key size")

func Encrypt(data []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(salt)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(append(salt, nonce...), ciphertext...), nil
}

func Decrypt(encryptedKey []byte) ([]byte, error) {
	if len(encryptedKey) < saltSize+nonceSize+1 {
		return nil, ErrInvalidKeySize
	}
	salt := encryptedKey[:saltSize]
	nonce := encryptedKey[saltSize : saltSize+nonceSize]
	ciphertext := encryptedKey[saltSize+nonceSize:]

	block, err := aes.NewCipher(salt)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
