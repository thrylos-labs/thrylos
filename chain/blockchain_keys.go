package chain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/scrypt"
)

const (
	keyLen    = 32 // AES-256
	nonceSize = 12
	saltSize  = 32
)

var ErrInvalidKeySize = errors.New("invalid key size")

func (bc *BlockchainImpl) RegisterPublicKey(pubKey crypto.PublicKey) error {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	// Save to database
	if err := bc.Blockchain.Database.SavePublicKey(pubKey); err != nil {
		return err
	}

	// Also cache in memory
	addr, err := pubKey.Address()
	if err != nil {
		return fmt.Errorf("failed to get address from public key: %v", err)
	}

	bc.Blockchain.PublicKeyMap[addr.String()] = &pubKey
	return nil
}

// // // In blockchain.go, within your Blockchain struct definition
func (bc *BlockchainImpl) RetrievePublicKey(validator string) ([]byte, error) {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()

	formattedAddress, err := shared.SanitizeAndFormatAddress(validator)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	log.Printf("Attempting to retrieve public key for address: %s", formattedAddress)

	// First, check if we already have a public key in memory
	if pubKeyPtr, ok := bc.Blockchain.PublicKeyMap[formattedAddress]; ok {
		log.Printf("Public key found in memory for address: %s", formattedAddress)
		// Dereference the pointer before calling Marshal()
		pubKeyBytes, err := (*pubKeyPtr).Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %v", err)
		}
		return pubKeyBytes, nil
	}

	// Try to parse the address
	addr, err := address.FromString(formattedAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	// Use the store's GetPublicKey method
	pubKey, err := bc.Blockchain.Database.GetPublicKey(*addr)
	if err != nil {
		log.Printf("Failed to retrieve public key from database: %v", err)
		return nil, err
	}

	// Cache the result in memory for future use
	bc.Blockchain.PublicKeyMap[formattedAddress] = &pubKey

	// Marshal the public key to bytes
	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	log.Printf("Successfully retrieved public key for address: %s", formattedAddress)
	return pubKeyBytes, nil
}

// // // // In Blockchain
func (bc *BlockchainImpl) InsertOrUpdatePublicKey(address string, publicKeyBytes []byte, keyType string) error {
	log.Printf("InsertOrUpdatePublicKey called with address: %s, keyType: %s", address, keyType)
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	if len(publicKeyBytes) == 0 {
		return fmt.Errorf("empty public key bytes provided")
	}
	log.Printf("PublicKey bytes: %x", publicKeyBytes)

	switch keyType {
	case "MLDSA":
		// Parse the bytes into an MLDSA public key
		mldsaPubKey := new(mldsa44.PublicKey)
		err := mldsaPubKey.UnmarshalBinary(publicKeyBytes)
		if err != nil {
			log.Printf("Failed to parse MLDSA public key for address %s: %v", address, err)
			return fmt.Errorf("failed to parse MLDSA public key: %v", err)
		}

		// Create a crypto.PublicKey from the MLDSA public key
		pubKey := crypto.NewPublicKey(mldsaPubKey)

		// Save to database using the standard method
		if err := bc.Blockchain.Database.SavePublicKey(pubKey); err != nil {
			log.Printf("Failed to store public key for address %s: %v", address, err)
			return fmt.Errorf("failed to store public key: %v", err)
		}

		// Update in-memory cache
		bc.Blockchain.PublicKeyMap[address] = &pubKey

		log.Printf("Successfully stored public key for address %s", address)
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func (bc *BlockchainImpl) EnsureTestValidatorRegistered(address string, publicKey mldsa44.PublicKey) error {
	// Check if the validator is already registered
	_, err := bc.RetrievePublicKey(address)
	if err == nil {
		// Validator is already registered
		return nil
	}

	// Serialize the public key to bytes
	publicKeyBytes := publicKey.Bytes()

	// Encode the public key to Base64
	pubKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Register the validator
	err = bc.RegisterValidator(address, pubKeyBase64, true)
	if err != nil {
		return fmt.Errorf("failed to register test validator: %v", err)
	}

	log.Printf("Registered test validator: %s", address)
	return nil
}

func deriveKey(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, keyLen)
}

func encryptPrivateKey(privKey *mldsa44.PrivateKey) ([]byte, error) {
	// Convert ML-DSA44 private key to bytes
	privKeyBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

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

	ciphertext := gcm.Seal(nil, nonce, privKeyBytes, nil)
	return append(append(salt, nonce...), ciphertext...), nil
}

func decryptPrivateKey(encryptedKey []byte) (*mldsa44.PrivateKey, error) {
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

	// Convert bytes back to ML-DSA44 private key
	var privKey mldsa44.PrivateKey
	err = privKey.UnmarshalBinary(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
	}

	return &privKey, nil
}

func (bc *BlockchainImpl) CheckValidatorKeyConsistency() error {
	log.Println("Checking validator key consistency")

	// Use stakeholders map instead of getting all validators from database
	bc.Blockchain.Mu.RLock()
	stakeholders := bc.Blockchain.Stakeholders
	activeValidators := bc.Blockchain.ActiveValidators
	bc.Blockchain.Mu.RUnlock()

	log.Printf("Total stakeholders: %d", len(stakeholders))
	log.Printf("Total active validators: %d", len(activeValidators))

	// Check stakeholders first
	for addressStr := range stakeholders {
		log.Printf("Checking consistency for stakeholder: %s", addressStr)

		// Parse address using the crypto package
		addr, err := address.FromString(addressStr)
		if err != nil {
			log.Printf("Invalid address format for stakeholder %s: %v", addressStr, err)
			continue
		}

		// Get public key from database
		storedPubKey, err := bc.Blockchain.Database.GetPublicKey(*addr)
		if err != nil {
			log.Printf("Failed to retrieve public key for stakeholder %s: %v", addressStr, err)
			continue
		}

		// Convert stored public key to bytes for logging
		storedPubKeyBytes, err := storedPubKey.Marshal()
		if err != nil {
			log.Printf("Failed to marshal stored public key for stakeholder %s: %v", addressStr, err)
			continue
		}
		log.Printf("Stored public key for %s: %x", addressStr, storedPubKeyBytes)

		if bc.IsActiveValidator(addressStr) {
			log.Printf("Stakeholder %s is an active validator", addressStr)

			privateKey, bech32Address, err := bc.GetValidatorPrivateKey(addressStr)
			if err != nil {
				log.Printf("Failed to retrieve private key for validator %s: %v", addressStr, err)
				continue
			}

			log.Printf("Retrieved private key for %s, Bech32 address: %s", addressStr, bech32Address)

			// Get public key from private key
			pubKey := privateKey.PublicKey()

			// Convert to bytes for comparison
			derivedPubKeyBytes, err := pubKey.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal derived public key for validator %s: %v", addressStr, err)
			}

			log.Printf("Derived public key for %s: %x", addressStr, derivedPubKeyBytes)

			if !bytes.Equal(storedPubKeyBytes, derivedPubKeyBytes) {
				log.Printf("Key mismatch for validator %s (Bech32: %s):", addressStr, bech32Address)
				log.Printf("  Stored public key:  %x", storedPubKeyBytes)
				log.Printf("  Derived public key: %x", derivedPubKeyBytes)
				return fmt.Errorf("key mismatch for active validator %s (Bech32: %s)", addressStr, bech32Address)
			}

			log.Printf("Keys consistent for active validator %s", addressStr)
		} else {
			log.Printf("Stakeholder %s is not an active validator", addressStr)
		}
	}

	// Check if all active validators have stored public keys and are stakeholders
	for _, activeAddress := range activeValidators {
		if _, isStakeholder := stakeholders[activeAddress]; !isStakeholder {
			log.Printf("Active validator %s is not a stakeholder", activeAddress)
			return fmt.Errorf("active validator %s is not a stakeholder", activeAddress)
		}

		addr, err := address.FromString(activeAddress)
		if err != nil {
			return fmt.Errorf("invalid active validator address format: %v", err)
		}

		_, err = bc.Blockchain.Database.GetPublicKey(*addr)
		if err != nil {
			log.Printf("Active validator %s does not have a stored public key", activeAddress)
			return fmt.Errorf("active validator %s does not have a stored public key", activeAddress)
		}
	}

	log.Println("Validator key consistency check completed")
	return nil
}

// Load all Validator public keys into Memory
func (bc *BlockchainImpl) LoadAllValidatorPublicKeys() error {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	log.Println("Loading all validator public keys")

	for addressStr := range bc.Blockchain.Stakeholders {
		log.Printf("Attempting to load public key for stakeholder: %s", addressStr)

		// Parse address using the correct package
		addr, err := address.FromString(addressStr)
		if err != nil {
			log.Printf("Invalid address format for stakeholder %s: %v", addressStr, err)
			continue
		}

		// Get public key using standard method
		pubKey, err := bc.Blockchain.Database.GetPublicKey(*addr)
		if err != nil {
			log.Printf("Failed to load public key for stakeholder %s: %v", addressStr, err)
			continue
		}

		// Store in memory cache
		bc.Blockchain.PublicKeyMap[addressStr] = &pubKey
		log.Printf("Loaded public key for validator: %s", addressStr)
	}

	log.Printf("Loaded public keys for %d validators", len(bc.Blockchain.PublicKeyMap))
	return nil
}
