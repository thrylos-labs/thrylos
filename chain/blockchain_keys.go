package chain

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
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

func (bc *BlockchainImpl) GetValidatorPrivateKey(validatorAddress string) (crypto.PrivateKey, string, error) {
	log.Printf("Attempting to retrieve private key for validator: %s", validatorAddress)

	// --- 1. Determine Genesis Address ---
	var genesisAddrStr string
	if bc.Blockchain.GenesisAccount != nil && bc.Blockchain.GenesisAccount.PublicKey() != nil {
		addr, err := bc.Blockchain.GenesisAccount.PublicKey().Address()
		if err != nil {
			// Log critical error but allow continuation; fallback might still be possible if address matches somehow,
			// but it's unlikely and indicates a setup problem.
			log.Printf("CRITICAL ERROR: Cannot get address from GenesisAccount public key in GetValidatorPrivateKey: %v", err)
		} else {
			genesisAddrStr = addr.String()
			log.Printf("DEBUG: Determined Genesis Address: %s", genesisAddrStr)
		}
	} else {
		// If GenesisAccount itself is nil, fallback is impossible.
		log.Println("WARN: GenesisAccount or its public key is nil in GetValidatorPrivateKey. Genesis fallback disabled.")
	}
	// --- End Determine Genesis Address ---

	// Determine if the requested address is the Genesis address
	isGenesis := (genesisAddrStr != "" && validatorAddress == genesisAddrStr)

	// --- 2. Check if Active Validator (Only if NOT Genesis) ---
	if !isGenesis {
		// Non-genesis validators MUST be in the active set to sign blocks.
		// Ensure IsActiveValidator handles necessary locking.
		isActive := bc.IsActiveValidator(validatorAddress)
		if !isActive {
			log.Printf("ERROR: Validator %s is not in the active validator list.", validatorAddress)
			// Return a specific error indicating the validator is not active
			return nil, "", fmt.Errorf("validator %s is not active", validatorAddress)
		}
		log.Printf("DEBUG: Validator %s confirmed active.", validatorAddress)
	} else {
		log.Printf("DEBUG: Requested validator %s is the Genesis address, skipping active check.", validatorAddress)
	}
	// --- End Check if Active Validator ---

	// --- 3. Retrieve Key from Keystore ---
	// Check if the ValidatorKeys store itself exists
	if bc.Blockchain.ValidatorKeys == nil {
		log.Println("ERROR: ValidatorKeys store (bc.Blockchain.ValidatorKeys) is nil.")
		// If the store doesn't exist, only fallback to Genesis is possible
		if isGenesis && bc.Blockchain.GenesisAccount != nil {
			log.Printf("DEBUG: ValidatorKeys store nil, falling back to GenesisAccount for %s.", validatorAddress)
			return bc.Blockchain.GenesisAccount, genesisAddrStr, nil
		}
		// Otherwise, we cannot retrieve the key
		return nil, "", fmt.Errorf("ValidatorKeys store is not initialized, cannot retrieve key for %s", validatorAddress)
	}

	// Attempt to get the key *pointer* from the store
	privateKeyPtr, exists := bc.Blockchain.ValidatorKeys.GetKey(validatorAddress)

	keyFoundInStore := false
	var cryptoPrivKey crypto.PrivateKey
	var retrievedAddress string

	if exists && privateKeyPtr != nil {
		log.Printf("DEBUG: Found non-nil private key pointer for %s in ValidatorKeys store.", validatorAddress)
		cryptoPrivKey = *privateKeyPtr // Dereference the pointer to get the actual key

		// --- 4. Verify Retrieved Key Ownership ---
		pubKey := cryptoPrivKey.PublicKey()
		if pubKey == nil {
			// This indicates a problem with the stored key object
			log.Printf("ERROR: Retrieved private key for %s has a nil public key.", validatorAddress)
			return nil, "", fmt.Errorf("retrieved key for %s has nil public key", validatorAddress)
		}
		// Derive address from the *retrieved* key's public key
		addrFromKey, err := pubKey.Address()
		if err != nil {
			log.Printf("ERROR: Failed to derive address from retrieved private key for %s: %v", validatorAddress, err)
			return nil, "", fmt.Errorf("error deriving address from retrieved key for %s: %w", validatorAddress, err)
		}
		retrievedAddress = addrFromKey.String()

		// Compare derived address with the requested address
		if retrievedAddress != validatorAddress {
			// Critical error: the key store returned a key belonging to someone else!
			log.Printf("CRITICAL ERROR: Keystore inconsistency! Key retrieved for %s actually belongs to %s.", validatorAddress, retrievedAddress)
			return nil, "", fmt.Errorf("keystore key mismatch for address %s (found key for %s)", validatorAddress, retrievedAddress)
		}

		// Key found and verified!
		keyFoundInStore = true
		log.Printf("DEBUG: Successfully retrieved and verified key for %s from keystore.", validatorAddress)

	} else if exists && privateKeyPtr == nil {
		// Log if GetKey returned exists=true but ptr=nil (indicates potential keystore issue)
		log.Printf("WARN: ValidatorKeys.GetKey returned exists=true but a nil pointer for %s. Keystore may be inconsistent.", validatorAddress)
		// Treat as if key was not found, fall through to Genesis check
	} else {
		// Key does not exist in the keystore
		log.Printf("DEBUG: Key for %s not found in ValidatorKeys store (exists=%v).", validatorAddress, exists)
		// Fall through to Genesis fallback check
	}
	// --- End Retrieve Key from Keystore ---

	// If found and verified in store, return it
	if keyFoundInStore {
		return cryptoPrivKey, retrievedAddress, nil
	}

	// --- 5. Fallback to Genesis Account ---
	// This section is reached only if the key was NOT found/verified in the keystore
	if isGenesis && bc.Blockchain.GenesisAccount != nil {
		log.Printf("DEBUG: Key for %s not found/verified in keystore, falling back to GenesisAccount.", validatorAddress)
		// Use the main GenesisAccount private key
		genesisPrivKey := bc.Blockchain.GenesisAccount
		// Return the genesis key and the previously determined genesis address string
		return genesisPrivKey, genesisAddrStr, nil
	}
	// --- End Fallback to Genesis Account ---

	// --- 6. Key Not Found ---
	// If we reach here, the key wasn't in the keystore, and it wasn't the Genesis address eligible for fallback.
	log.Printf("ERROR: Failed to retrieve private key for validator %s. Not in keystore and not Genesis fallback.", validatorAddress)
	return nil, "", fmt.Errorf("private key not found or accessible for validator %s", validatorAddress)
	// --- End Key Not Found ---
}
