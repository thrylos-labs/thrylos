package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/blake2b"
)

var blake2bHasher, _ = blake2b.New256(nil)

// GenerateAESKey generates a new AES-256 symmetric key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptWithAES encrypts data using AES-256-CBC.
func EncryptWithAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func EncryptAESKey(aesKey []byte, recipientPublicKey *rsa.PublicKey) ([]byte, error) {
	// Use SHA-256 for OAEP, which is standard and safe for this purpose
	hasher := sha256.New()

	// The third parameter here is the hash used for OAEP, not the key or data itself
	encryptedKey, err := rsa.EncryptOAEP(
		hasher,
		rand.Reader,
		recipientPublicKey,
		aesKey,
		nil, // Often no label is used, hence nil
	)
	if err != nil {
		return nil, err
	}
	return encryptedKey, nil
}
