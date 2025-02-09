package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// DecryptWithAES decrypts data using AES-256-CBC.
func DecryptWithAES(key, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encryptedData) < aes.BlockSize {
		return nil, errors.New("encryptedData too short")
	}
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	data := make([]byte, len(encryptedData))
	stream.XORKeyStream(data, encryptedData)
	return data, nil
}
