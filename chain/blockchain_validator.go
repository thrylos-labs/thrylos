package chain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"time"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
)

// StartPeriodicValidatorUpdate periodically calls UpdateActiveValidators
func (bc *BlockchainImpl) StartPeriodicValidatorUpdate(interval time.Duration, count int) {
	log.Printf("Starting periodic validator update every %v, selecting top %d validators", interval, count)
	ticker := time.NewTicker(interval)
	defer ticker.Stop() // Ensure ticker is stopped when goroutine exits

	// Perform an initial update immediately
	log.Println("Performing initial active validator update...")
	bc.UpdateActiveValidators(count)

	// Then update periodically
	for range ticker.C {
		log.Println("Ticker triggered: Updating active validators...")
		bc.UpdateActiveValidators(count)
	}
	log.Println("Stopping periodic validator update.") // Should ideally not be reached unless chain stops
}

func (bc *BlockchainImpl) RegisterValidator(address string, pubKey string, bypassStakeCheck bool) error {
	log.Printf("Entering RegisterValidator function for address: %s", address)

	lockChan := make(chan struct{})
	go func() {
		bc.Blockchain.Mu.Lock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		log.Printf("Lock acquired for address: %s", address)
		defer func() {
			bc.Blockchain.Mu.Unlock()
			log.Printf("Lock released for address: %s", address)
		}()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout while acquiring lock for address: %s", address)
	}

	// Sanitize and format the address
	formattedAddress, err := shared.SanitizeAndFormatAddress(address)
	if err != nil {
		log.Printf("Invalid address format for %s: %v", address, err)
		return fmt.Errorf("invalid address format: %v", err)
	}
	log.Printf("Formatted address: %s", formattedAddress)

	// Decode base64 public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	// Create and parse MLDSA public key
	mldsaPubKey := new(mldsa44.PublicKey)
	err = mldsaPubKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid MLDSA public key format: %v", err)
	}

	// Convert MLDSA public key to crypto.PublicKey
	cryptoPubKey := crypto.NewPublicKey(mldsaPubKey)

	// Store a pointer to the interface
	var pubKeyInterface crypto.PublicKey = cryptoPubKey
	bc.Blockchain.PublicKeyMap[formattedAddress] = &pubKeyInterface

	log.Printf("Stored public key in memory for address: %s", formattedAddress)

	// Validate stake if not bypassing check
	if !bypassStakeCheck {
		stake, exists := bc.Blockchain.Stakeholders[formattedAddress]
		if !exists || stake < bc.Blockchain.MinStakeForValidator.Int64() {
			log.Printf("Insufficient stake for %s: exists=%v, stake=%d, minStake=%d",
				formattedAddress, exists, stake, bc.Blockchain.MinStakeForValidator.Int64())
			return fmt.Errorf("insufficient stake or not found")
		}
	}
	log.Printf("Stake check bypassed or passed for %s", formattedAddress)

	// Store in the database with a timeout
	log.Printf("Attempting to store public key in database for address: %s", formattedAddress)
	dbChan := make(chan error, 1)
	go func() {
		// Convert MLDSA public key to crypto.PublicKey
		cryptoPubKey := crypto.NewPublicKey(mldsaPubKey)

		// Save the wrapped public key
		dbChan <- bc.Blockchain.Database.SavePublicKey(cryptoPubKey)
	}()

	select {
	case err := <-dbChan:
		if err != nil {
			log.Printf("Failed to store public key in database for %s: %v", formattedAddress, err)
			return fmt.Errorf("failed to store public key in database: %v", err)
		}
	case <-time.After(5 * time.Second):
		log.Printf("Database operation timed out for %s", formattedAddress)
		return fmt.Errorf("database operation timed out")
	}

	log.Printf("Successfully stored public key in database for address: %s", formattedAddress)

	// Assign the minimum stake to the new validator
	minStake := bc.Blockchain.MinStakeForValidator.Int64()
	bc.Blockchain.Stakeholders[formattedAddress] = minStake
	log.Printf("Assigned minimum stake %d to validator %s", minStake, formattedAddress)

	log.Printf("Validator registered successfully: address=%s", formattedAddress)
	return nil
}

func (bc *BlockchainImpl) StoreValidatorPrivateKey(address string, privKeyBytes []byte) error {
	log.Printf("Storing private key for validator: %s", address)

	// Create and parse MLDSA private key
	mldsaPrivKey := new(mldsa44.PrivateKey)
	err := mldsaPrivKey.UnmarshalBinary(privKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse MLDSA private key for validator %s: %v", address, err)
	}

	// Create a new crypto.PrivateKey using NewPrivateKeyFromMLDSA
	cryptoPrivKey := crypto.NewPrivateKeyFromMLDSA(mldsaPrivKey)

	// Create an interface variable
	var privKeyInterface crypto.PrivateKey = cryptoPrivKey

	// Store the pointer to the interface
	if err := bc.Blockchain.ValidatorKeys.StoreKey(address, &privKeyInterface); err != nil {
		log.Printf("Failed to store private key for validator %s: %v", address, err)
		return fmt.Errorf("failed to store private key for validator %s: %v", address, err)
	}

	log.Printf("Private key for validator %s stored securely", address)
	return nil
}

// // For generating multiple Validator Keys if necessary
func (bc *BlockchainImpl) GenerateAndStoreValidatorKeys(count int, addr string) ([]string, error) {
	log.Printf("Starting to generate and store %d validator keys", count)
	validatorAddresses := make([]string, 0, count)

	for i := 0; i < count; i++ {
		log.Printf("Generating validator key %d of %d", i+1, count)

		// Generate validator address (renamed from 'address' to 'validatorAddress')
		validatorAddress, err := GenerateValidatorAddress()
		if err != nil {
			log.Printf("Failed to generate validator address: %v", err)
			return validatorAddresses, fmt.Errorf("failed to generate validator address: %v", err)
		}

		// Generate MLDSA key pair directly
		pubKey, privKey, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("Failed to generate MLDSA key pair: %v", err)
			return validatorAddresses, fmt.Errorf("failed to generate MLDSA key pair: %v", err)
		}

		// Convert MLDSA private key to crypto.PrivateKey
		cryptoPrivKey := crypto.NewPrivateKeyFromMLDSA(privKey)

		// Create an interface variable and store its pointer
		var privKeyInterface crypto.PrivateKey = cryptoPrivKey
		err = bc.Blockchain.ValidatorKeys.StoreKey(validatorAddress, &privKeyInterface)
		if err != nil {
			log.Printf("Failed to store validator private key: %v", err)
			return validatorAddresses, fmt.Errorf("failed to store validator private key: %v", err)
		}

		// Convert MLDSA public key to crypto.PublicKey and store it
		cryptoPubKey := crypto.NewPublicKey(pubKey)

		err = bc.Blockchain.Database.SavePublicKey(cryptoPubKey)
		if err != nil {
			log.Printf("Failed to store validator public key: %v", err)
			return validatorAddresses, fmt.Errorf("failed to store validator public key: %v", err)
		}

		// Convert string address to Address type using the package function
		validatorAddr, err := address.FromString(addr) // Now 'address' refers to the package
		if err != nil {
			log.Printf("Failed to convert address string to Address type: %v", err)
			return validatorAddresses, fmt.Errorf("failed to convert address: %v", err)
		}

		// Verify the key was stored correctly by retrieving it
		storedPubKey, err := bc.Blockchain.Database.GetPublicKey(*validatorAddr)
		if err != nil {
			log.Printf("Error retrieving validator public key immediately after storage: %v", err)
			return validatorAddresses, fmt.Errorf("failed to verify stored validator key: %v", err)
		}

		// Verify the stored key matches the original using interface methods
		if !cryptoPubKey.Equal(&storedPubKey) {
			log.Printf("Stored public key does not match generated key for address %s", validatorAddress)
			return validatorAddresses, fmt.Errorf("key verification failed for address %s", validatorAddress)
		}

		// Store the public key in the PublicKeyMap
		var pubKeyInterface crypto.PublicKey = cryptoPubKey
		bc.Blockchain.PublicKeyMap[validatorAddress] = &pubKeyInterface

		log.Printf("Successfully generated and stored validator key %d: %s", i+1, validatorAddress)
		validatorAddresses = append(validatorAddresses, validatorAddress)
	}

	log.Printf("Finished generating and storing %d validator keys", len(validatorAddresses))
	return validatorAddresses, nil
}

func (bc *BlockchainImpl) GetValidatorPublicKey(validatorAddress string) (*mldsa44.PublicKey, error) {
	// Use the improved address.Validate which checks HRP and length
	if !address.Validate(validatorAddress) {
		return nil, fmt.Errorf("invalid validator address format or content: %s", validatorAddress)
	}

	// Use address.FromString to get the address object directly.
	// This is cleaner than decoding again.
	addrPtr, err := address.FromString(validatorAddress)
	if err != nil {
		// This ideally shouldn't happen if address.Validate passed, indicates internal inconsistency
		log.Printf("ERROR: Failed to get address object from validated string '%s': %v", validatorAddress, err)
		return nil, fmt.Errorf("internal error converting validated address string: %v", err)
	}
	addr := *addrPtr // Dereference pointer if GetPublicKey expects the value type address.Address

	// Get the public key using the store's method, passing the address object
	// Assuming bc.Blockchain.Database.GetPublicKey expects address.Address type
	pubKey, err := bc.Blockchain.Database.GetPublicKey(addr)
	if err != nil {
		// Log the specific address object used for lookup might be helpful
		log.Printf("DEBUG: Failed GetPublicKey lookup for address object: %+v", addr)
		return nil, fmt.Errorf("failed to get public key for validator %s from DB: %v", validatorAddress, err)
	}

	// Ensure pubKey is not nil (depends on how GetPublicKey indicates "not found" vs other errors)
	if pubKey == nil { // You might need a more specific check depending on crypto.PublicKey type
		return nil, fmt.Errorf("public key not found in DB for validator %s", validatorAddress)
	}

	// Convert crypto.PublicKey to bytes (assuming it has a Marshal method)
	pubKeyBytes, err := pubKey.Marshal() // Use the retrieved crypto.PublicKey
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for validator %s: %v", validatorAddress, err)
	}
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("marshaled public key is empty for validator %s", validatorAddress)
	}

	log.Printf("DEBUG: [GetValidatorPublicKey] Bytes from pubKey.Marshal() for %s: %x", validatorAddress, pubKeyBytes) // Log bytes BEFORE unmarshal attempt

	// Create and unmarshal into MLDSA44 public key
	mldsa44PubKey := new(mldsa44.PublicKey)
	err = mldsa44PubKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		// Log the bytes that failed to unmarshal for debugging
		log.Printf("ERROR: Failed to unmarshal MLDSA44 key for %s. Bytes (hex): %x", validatorAddress, pubKeyBytes)
		return nil, fmt.Errorf("failed to convert DB key to MLDSA44 public key for validator %s: %v", validatorAddress, err)
	}

	log.Printf("DEBUG: [GetValidatorPublicKey] Successfully unmarshalled MLDSA44 key for %s", validatorAddress)

	return mldsa44PubKey, nil
}

// Keep the other functions as they were, they seem okay:
func (bc *BlockchainImpl) validatorExists(addr string) bool {
	// Convert string to Address type using the package function
	validatorAddr, err := address.FromString(addr)
	if err != nil {
		log.Printf("Failed to convert address string to Address type: %v", err)
		return false
	}

	// Use the Address type with GetPublicKey
	_, err = bc.Blockchain.Database.GetPublicKey(*validatorAddr)
	return err == nil
}

func (bc *BlockchainImpl) IsActiveValidator(address string) bool {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()

	for _, validator := range bc.Blockchain.ActiveValidators {
		if validator == address {
			return true
		}
	}
	return false
}

func (bc *BlockchainImpl) UpdateActiveValidators(count int) {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	// Sort stakeholders by stake amount
	type validatorStake struct {
		address string
		amount  int64 // Keep as int64 for sorting ease
	}
	validators := make([]validatorStake, 0)

	// --- MODIFICATION START ---
	// Get the minimum stake required from the Blockchain struct field
	minStakeRequiredBigInt := bc.Blockchain.MinStakeForValidator
	if minStakeRequiredBigInt == nil {
		log.Printf("WARN: MinStakeForValidator is nil in UpdateActiveValidators. Using default 0.")
		minStakeRequiredBigInt = big.NewInt(0) // Avoid nil pointer panic, default to 0 or log error
	}
	// Convert the big.Int minimum stake to int64 for comparison.
	// NOTE: This assumes the stake amounts won't exceed the limits of int64.
	// If stakes can be larger, you might need to use big.Int throughout.
	minStakeRequiredInt64 := minStakeRequiredBigInt.Int64()
	log.Printf("DEBUG: [UpdateActiveValidators] Minimum stake required: %d nanoTHR", minStakeRequiredInt64)
	// --- MODIFICATION END ---

	for addr, stake := range bc.Blockchain.Stakeholders {
		// --- MODIFICATION START ---
		// Compare the stakeholder's stake (int64) with the required minimum (int64)
		if stake >= minStakeRequiredInt64 {
			// Log the validator being considered
			log.Printf("DEBUG: [UpdateActiveValidators] Considering validator %s with stake %d (>= %d)", addr, stake, minStakeRequiredInt64)
			validators = append(validators, validatorStake{addr, stake})
		}
		// --- MODIFICATION END ---
	}

	// Sort by stake amount (descending)
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].amount > validators[j].amount
	})

	// Determine the actual number of validators to activate
	numToActivate := count
	if count > len(validators) {
		log.Printf("WARN: [UpdateActiveValidators] Requested count %d exceeds available eligible validators %d. Activating all eligible.", count, len(validators))
		numToActivate = len(validators)
	}

	// Update active validators list
	newActiveValidators := make([]string, 0, numToActivate)
	log.Printf("INFO: [UpdateActiveValidators] Updating active validators (Top %d):", numToActivate)
	for i := 0; i < numToActivate; i++ {
		newActiveValidators = append(newActiveValidators, validators[i].address)
		log.Printf("  - %d: %s (Stake: %d)", i+1, validators[i].address, validators[i].amount)
	}

	// Check if the list actually changed before assigning and resetting index
	currentActiveValidators := bc.Blockchain.ActiveValidators
	sort.Strings(currentActiveValidators) // Sort for comparison
	sort.Strings(newActiveValidators)     // Sort for comparison

	if !equalStringSlices(currentActiveValidators, newActiveValidators) {
		log.Printf("INFO: [UpdateActiveValidators] Active validator set changed. New set has %d validators.", len(newActiveValidators))
		bc.Blockchain.ActiveValidators = newActiveValidators // Assign the potentially new list
		bc.Blockchain.NextValidatorIndex = 0                 // Reset index when the list changes
	} else {
		log.Printf("DEBUG: [UpdateActiveValidators] Active validator set remains unchanged (%d validators).", len(newActiveValidators))
	}
}

// Helper function to compare sorted string slices
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// // GetMinStakeForValidator returns the current minimum stake required for a validator
func (bc *BlockchainImpl) GetMinStakeForValidator() *big.Int {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()
	return new(big.Int).Set(bc.Blockchain.MinStakeForValidator) // Return a copy to prevent modification
}

// // // You might also want to add a setter method if you need to update this value dynamically
func (bc *BlockchainImpl) SetMinStakeForValidator(newMinStake *big.Int) {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()
	bc.Blockchain.MinStakeForValidator = new(big.Int).Set(newMinStake)
}

func (bc *BlockchainImpl) SlashMaliciousValidator(validatorAddress string, slashAmount int64) {
	if _, ok := bc.Blockchain.Stakeholders[validatorAddress]; ok {
		// Deduct the slashAmount from the stake
		bc.Blockchain.Stakeholders[validatorAddress] -= slashAmount
		if bc.Blockchain.Stakeholders[validatorAddress] <= 0 {
			// Remove validator if their stake goes to zero or negative
			delete(bc.Blockchain.Stakeholders, validatorAddress)
		}
	}
}

func (bc *BlockchainImpl) IsSlashed(validator string) bool {
	// Check if validator is in slashed state
	if stake, exists := bc.Blockchain.Stakeholders[validator]; exists {
		return stake < bc.Blockchain.MinStakeForValidator.Int64() // Validator is slashed if below min stake
	}
	return false
}

func GenerateValidatorAddress() (string, error) {
	// Generate a random 32-byte seed
	seed := new([mldsa44.SeedSize]byte)
	_, err := rand.Read(seed[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate seed: %v", err)
	}

	// Generate ML-DSA-44 private and public keys from the seed
	publicKey, privateKey := mldsa44.NewKeyFromSeed(seed)
	_ = privateKey // Private key can be stored securely if needed

	// Serialize the public key
	publicKeyBytes := publicKey.Bytes()

	// Hash the public key
	hash := sha256.Sum256(publicKeyBytes)

	// Use the first 20 bytes of the hash as the address bytes
	addressBytes := hash[:20]

	// Convert to 5-bit groups for bech32 encoding
	converted, err := bech32.ConvertBits(addressBytes, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %v", err)
	}

	// Encode using bech32
	address, err := bech32.Encode("tl1", converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %v", err)
	}

	return address, nil
}

func (bc *BlockchainImpl) GenerateAndStoreValidatorKey() (string, error) {
	address, err := GenerateValidatorAddress()
	if err != nil {
		return "", fmt.Errorf("failed to generate validator address: %v", err)
	}

	// Generate MLDSA key pair directly
	pubKey, privKey, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate MLDSA key pair: %v", err)
	}

	// Wrap the MLDSA private key in your crypto package's type
	cryptoPrivKey := crypto.NewPrivateKeyFromMLDSA(privKey)

	// Marshal the public key
	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Register the validator
	err = bc.RegisterValidator(address, pubKeyBase64, true)
	if err != nil {
		return "", fmt.Errorf("failed to register validator: %v", err)
	}

	// Store the private key
	err = bc.Blockchain.ValidatorKeys.StoreKey(address, &cryptoPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to store validator private key: %v", err)
	}

	return address, nil
}

func (bc *BlockchainImpl) GetActiveValidators() []string {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()
	return bc.Blockchain.ActiveValidators
}

func (bc *BlockchainImpl) SelectNextValidator() (string, error) {
	bc.Blockchain.Mu.Lock() // Lock needed to read ActiveValidators and read/write NextValidatorIndex safely
	defer bc.Blockchain.Mu.Unlock()

	if len(bc.Blockchain.ActiveValidators) == 0 {
		// Fallback to Genesis if no active validators and Genesis key exists
		if bc.Blockchain.GenesisAccount != nil && bc.Blockchain.GenesisAccount.PublicKey() != nil {
			addr, err := bc.Blockchain.GenesisAccount.PublicKey().Address()
			if err != nil {
				log.Printf("ERROR: Cannot get Genesis address for fallback validator selection: %v", err)
				return "", errors.New("no active validators and failed to get genesis address")
			}
			log.Printf("WARN: No active validators defined, falling back to Genesis Account: %s", addr.String())
			return addr.String(), nil // Return Genesis address
		}
		log.Printf("ERROR: No active validators available for selection and GenesisAccount is not configured.")
		return "", errors.New("no active validators available for selection")
	}

	// Ensure index wraps around correctly
	// Use modulo operator for cleaner wrap-around
	currentIndex := bc.Blockchain.NextValidatorIndex % len(bc.Blockchain.ActiveValidators)

	selectedValidator := bc.Blockchain.ActiveValidators[currentIndex]
	log.Printf("Selected validator index %d: %s", currentIndex, selectedValidator)

	// Increment index for the next call, wrapping around using modulo
	bc.Blockchain.NextValidatorIndex = (currentIndex + 1) // No need for explicit modulo here if we calculate currentIndex each time

	return selectedValidator, nil
}
