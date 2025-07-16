package chain

import (
	"bytes"
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
func (bc *BlockchainImpl) StartPeriodicValidatorUpdate(interval time.Duration, maxValidators int, initialDone chan<- struct{}) {
	log.Printf("Starting periodic validator update every %v, selecting top %d validators", interval, maxValidators)

	// Perform initial update immediately
	bc.UpdateActiveValidators(maxValidators) // This should populate blockchain.Blockchain.ActiveValidators

	// Signal that initial update is done, immediately after it completes
	// Check if initialDone is not nil, just in case (though it should be here)
	if initialDone != nil {
		close(initialDone) // <--- CRITICAL: Close the channel to unblock the waiter
		initialDone = nil  // Avoid closing again if this func gets called differently
	}

	// Set up ticker for subsequent updates
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Ticker triggered: Updating active validators...")
		bc.UpdateActiveValidators(maxValidators)
	}
}

func (bc *BlockchainImpl) RegisterValidator(address string, pubKey string, bypassStakeCheck bool) error {
	log.Printf("Entering RegisterValidator function for address: %s", address)

	lockChan := make(chan struct{})
	go func() {
		bc.ShardState.Mu.Lock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		log.Printf("Lock acquired for address: %s", address)
		defer func() {
			bc.ShardState.Mu.Unlock()
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
	bc.ShardState.PublicKeyMap[formattedAddress] = &pubKeyInterface

	log.Printf("Stored public key in memory for address: %s", formattedAddress)

	// Validate stake if not bypassing check
	if !bypassStakeCheck {
		stake, exists := bc.ShardState.Stakeholders[formattedAddress]
		if !exists || stake < bc.ShardState.MinStakeForValidator.Int64() {
			log.Printf("Insufficient stake for %s: exists=%v, stake=%d, minStake=%d",
				formattedAddress, exists, stake, bc.ShardState.MinStakeForValidator.Int64())
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
		dbChan <- bc.ShardState.Database.SavePublicKey(cryptoPubKey)
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
	minStake := bc.ShardState.MinStakeForValidator.Int64()
	bc.ShardState.Stakeholders[formattedAddress] = minStake
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
	if err := bc.ShardState.ValidatorKeys.StoreKey(address, &privKeyInterface); err != nil {
		log.Printf("Failed to store private key for validator %s: %v", address, err)
		return fmt.Errorf("failed to store private key for validator %s: %v", address, err)
	}

	log.Printf("Private key for validator %s stored securely", address)
	return nil
}

func (bc *BlockchainImpl) GenerateAndStoreValidatorKeys(count int) ([]string, error) {
	log.Printf("Starting to generate and store %d validator keys", count)
	generatedAddresses := make([]string, 0, count)

	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	for i := 0; i < count; i++ {
		log.Printf("Generating validator key %d of %d", i+1, count)

		// --- Step 1: Generate Key Pair ---
		pubKey, privKey, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("Failed to generate MLDSA key pair: %v", err)
			return generatedAddresses, fmt.Errorf("failed to generate MLDSA key pair: %w", err)
		}

		// --- Step 2: Wrap Keys in crypto interfaces ---
		cryptoPrivKey := crypto.NewPrivateKeyFromMLDSA(privKey)
		cryptoPubKey := crypto.NewPublicKey(pubKey)

		// --- Step 3: Derive Address from the generated Public Key ---
		derivedAddr, err := cryptoPubKey.Address()
		if err != nil {
			log.Printf("Failed to derive address from generated public key: %v", err)
			return generatedAddresses, fmt.Errorf("failed to derive address from generated public key: %w", err)
		}
		derivedAddressString := derivedAddr.String()
		log.Printf("DEBUG: Generated key pair, derived address: %s", derivedAddressString)

		// --- Step 4: Store Private Key using SaveValidatorKey (which uses derived address) ---
		err = bc.ShardState.ValidatorKeys.SaveValidatorKey(cryptoPrivKey)
		if err != nil {
			log.Printf("Failed to store validator private key for derived address %s: %v", derivedAddressString, err)
			return generatedAddresses, fmt.Errorf("failed to store validator private key for %s: %w", derivedAddressString, err)
		}

		// --- Step 5: Store Public Key ---
		err = bc.ShardState.Database.SavePublicKey(cryptoPubKey)
		if err != nil {
			log.Printf("Failed to store validator public key for derived address %s: %v", derivedAddressString, err)
			return generatedAddresses, fmt.Errorf("failed to store validator public key for %s: %w", derivedAddressString, err)
		}

		// --- Step 6: Store Public Key in In-Memory Map ---
		var pubKeyInterface crypto.PublicKey = cryptoPubKey
		bc.ShardState.PublicKeyMap[derivedAddressString] = &pubKeyInterface

		// --- Step 7: Add to Stakeholders with minimum stake ---
		minStake := bc.ShardState.MinStakeForValidator.Int64()
		bc.ShardState.Stakeholders[derivedAddressString] = minStake
		log.Printf("Added validator %s to stakeholders with minimum stake: %d", derivedAddressString, minStake)

		// --- Step 8: Verification ---
		retrievedPrivKeyPtr, exists := bc.ShardState.ValidatorKeys.GetKey(derivedAddressString)
		if !exists || retrievedPrivKeyPtr == nil || *retrievedPrivKeyPtr == nil {
			log.Printf("CRITICAL: Failed to retrieve private key %s from cache immediately after storing", derivedAddressString)
			return generatedAddresses, fmt.Errorf("failed to verify private key storage in cache for %s", derivedAddressString)
		}

		// --- Step 9: Record generated address ---
		log.Printf("Successfully generated and stored validator key %d: %s", i+1, derivedAddressString)
		generatedAddresses = append(generatedAddresses, derivedAddressString)
	}

	log.Printf("Finished generating and storing %d validator keys", len(generatedAddresses))
	return generatedAddresses, nil
}

// ADDITIONAL FIX: Add a method to debug and fix any existing validator key mismatches
func (bc *BlockchainImpl) DebugAndFixValidatorKeys() error {
	log.Printf("=== DEBUGGING VALIDATOR KEYS ===")

	// Get all stored keys
	storedKeys := bc.ShardState.ValidatorKeys.GetAllAddresses()
	log.Printf("Stored private keys: %d", len(storedKeys))
	for _, addr := range storedKeys {
		log.Printf("  - %s", addr)
	}

	// Get active validators
	activeValidators := bc.GetActiveValidators()
	log.Printf("Active validators: %d", len(activeValidators))

	missingKeys := []string{}
	for i, addr := range activeValidators {
		log.Printf("  %d: %s", i+1, addr)

		// Check if we have the private key
		if _, exists := bc.ShardState.ValidatorKeys.GetKey(addr); exists {
			log.Printf("    ✓ Private key found")
		} else {
			log.Printf("    ✗ Private key NOT found")
			missingKeys = append(missingKeys, addr)
		}
	}

	// If there are missing keys, try to regenerate them
	if len(missingKeys) > 0 {
		log.Printf("FIXING: Found %d active validators without private keys", len(missingKeys))

		// Clear the active validators list temporarily
		bc.ShardState.Mu.Lock()
		bc.ShardState.ActiveValidators = []string{}
		bc.ShardState.Mu.Unlock()

		// Generate new validator keys
		newValidators, err := bc.GenerateAndStoreValidatorKeys(len(missingKeys))
		if err != nil {
			return fmt.Errorf("failed to regenerate validator keys: %v", err)
		}

		log.Printf("Generated %d new validator keys to replace missing ones", len(newValidators))

		// Update active validators with the new ones
		bc.UpdateActiveValidators(5) // Update with your desired count
	}

	log.Printf("=== END VALIDATOR KEY DEBUG ===")
	return nil
}

func (bc *BlockchainImpl) GetValidatorPublicKey(validatorAddress string) (*mldsa44.PublicKey, error) {
	// Use the improved address.Validate which checks HRP and length
	if !address.Validate(validatorAddress) {
		return nil, fmt.Errorf("invalid validator address format or content: %s", validatorAddress)
	}

	// Use address.FromString to get the address object directly.
	addrPtr, err := address.FromString(validatorAddress)
	if err != nil {
		log.Printf("ERROR: Failed to get address object from validated string '%s': %v", validatorAddress, err)
		return nil, fmt.Errorf("internal error converting validated address string: %v", err)
	}
	addr := *addrPtr

	// Get the public key using the store's method
	// This returns your *wrapper* type (crypto.PublicKey)
	pubKeyWrapper, err := bc.ShardState.Database.GetPublicKey(addr) // Assuming this returns crypto.PublicKey
	if err != nil {
		log.Printf("DEBUG: Failed GetPublicKey lookup for address object: %+v", addr)
		return nil, fmt.Errorf("failed to get public key for validator %s from DB: %v", validatorAddress, err)
	}

	if pubKeyWrapper == nil { // Check the wrapper object
		return nil, fmt.Errorf("public key wrapper not found in DB for validator %s", validatorAddress)
	}

	// Marshal the *wrapper* public key to bytes
	// This uses YOUR Marshal method on the crypto.PublicKey wrapper
	pubKeyBytes, err := pubKeyWrapper.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key wrapper for validator %s: %v", validatorAddress, err)
	}
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("marshaled public key wrapper bytes are empty for validator %s", validatorAddress)
	}

	// Log the bytes produced by your wrapper's Marshal() method
	log.Printf("DEBUG: [GetValidatorPublicKey] Bytes from pubKeyWrapper.Marshal() for %s [Len: %d]: %x", validatorAddress, len(pubKeyBytes), pubKeyBytes)

	// Create and unmarshal into the specific *MLDSA44* public key type
	// This uses the UnmarshalBinary method from the mldsa44 library
	mldsa44PubKey := new(mldsa44.PublicKey) // Use the correct type
	err = mldsa44PubKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		log.Printf("ERROR: Failed to unmarshal into MLDSA44 key for %s. Bytes used (hex): %x", validatorAddress, pubKeyBytes)
		return nil, fmt.Errorf("failed to convert DB key bytes to MLDSA44 public key for validator %s: %v", validatorAddress, err)
	}

	log.Printf("DEBUG: [GetValidatorPublicKey] Successfully unmarshalled MLDSA44 key for %s", validatorAddress)

	// --- ROUND TRIP VERIFICATION ---
	log.Printf("DEBUG: [GetValidatorPublicKey] Performing round-trip check for %s...", validatorAddress)
	// Marshal the *mldsa44PubKey* object back into bytes using its *own* method (e.g., Bytes() or MarshalBinary())
	// Assuming the mldsa44.PublicKey type has a Bytes() method for its canonical representation:
	remarshaledBytes := mldsa44PubKey.Bytes()
	// If it has MarshalBinary instead:
	// remarshaledBytes, err := mldsa44PubKey.MarshalBinary()
	// if err != nil {
	//     log.Printf("ERROR: [GetValidatorPublicKey] Failed to re-marshal mldsa44PubKey for round-trip check: %v", err)
	//     // Decide if this should be a fatal error for the function
	//     // return nil, fmt.Errorf("failed round-trip check (re-marshal error): %v", err)
	// }

	log.Printf("DEBUG: [GetValidatorPublicKey] Original marshaled wrapper bytes [Len: %d]: %x", len(pubKeyBytes), pubKeyBytes)
	log.Printf("DEBUG: [GetValidatorPublicKey] Re-marshaled mldsa44 bytes [Len: %d]: %x", len(remarshaledBytes), remarshaledBytes)

	// Compare the original bytes (from wrapper Marshal) with the re-marshaled bytes (from mldsa44 object)
	if bytes.Equal(pubKeyBytes, remarshaledBytes) {
		log.Printf("INFO: [GetValidatorPublicKey] Round-trip successful! Bytes match for %s.", validatorAddress)
	} else {
		log.Printf("ERROR: [GetValidatorPublicKey] Round-trip FAILED! Byte mismatch for %s.", validatorAddress)
		// Depending on requirements, you might want to return an error here
		// return nil, fmt.Errorf("public key round-trip verification failed for %s", validatorAddress)
	}
	// --- END ROUND TRIP VERIFICATION ---

	// Return the unmarshalled mldsa44 public key object
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
	_, err = bc.ShardState.Database.GetPublicKey(*validatorAddr)
	return err == nil
}

func (bc *BlockchainImpl) IsActiveValidator(address string) bool {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()

	for _, validator := range bc.ShardState.ActiveValidators {
		if validator == address {
			return true
		}
	}
	return false
}

func (bc *BlockchainImpl) UpdateActiveValidators(count int) {
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	// Sort stakeholders by stake amount
	type validatorStake struct {
		address string
		amount  int64 // Keep as int64 for sorting ease
	}
	validators := make([]validatorStake, 0)

	// --- MODIFICATION START ---
	// Get the minimum stake required from the Blockchain struct field
	minStakeRequiredBigInt := bc.ShardState.MinStakeForValidator
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

	for addr, stake := range bc.ShardState.Stakeholders {
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
	currentActiveValidators := bc.ShardState.ActiveValidators
	sort.Strings(currentActiveValidators) // Sort for comparison
	sort.Strings(newActiveValidators)     // Sort for comparison

	if !equalStringSlices(currentActiveValidators, newActiveValidators) {
		log.Printf("INFO: [UpdateActiveValidators] Active validator set changed. New set has %d validators.", len(newActiveValidators))
		bc.ShardState.ActiveValidators = newActiveValidators // Assign the potentially new list
		bc.ShardState.NextValidatorIndex = 0                 // Reset index when the list changes
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
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	return new(big.Int).Set(bc.ShardState.MinStakeForValidator) // Return a copy to prevent modification
}

// // // You might also want to add a setter method if you need to update this value dynamically
func (bc *BlockchainImpl) SetMinStakeForValidator(newMinStake *big.Int) {
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()
	bc.ShardState.MinStakeForValidator = new(big.Int).Set(newMinStake)
}

func (bc *BlockchainImpl) SlashMaliciousValidator(validatorAddress string, slashAmount int64) {
	if _, ok := bc.ShardState.Stakeholders[validatorAddress]; ok {
		// Deduct the slashAmount from the stake
		bc.ShardState.Stakeholders[validatorAddress] -= slashAmount
		if bc.ShardState.Stakeholders[validatorAddress] <= 0 {
			// Remove validator if their stake goes to zero or negative
			delete(bc.ShardState.Stakeholders, validatorAddress)
		}
	}
}

func (bc *BlockchainImpl) IsSlashed(validator string) bool {
	// Check if validator is in slashed state
	if stake, exists := bc.ShardState.Stakeholders[validator]; exists {
		return stake < bc.ShardState.MinStakeForValidator.Int64() // Validator is slashed if below min stake
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
	err = bc.ShardState.ValidatorKeys.SaveValidatorKey(cryptoPrivKey) // New call
	if err != nil {
		return "", fmt.Errorf("failed to store validator private key: %v", err)
	}

	return address, nil
}

func (bc *BlockchainImpl) GetActiveValidators() []string {
	bc.ShardState.Mu.RLock()
	defer bc.ShardState.Mu.RUnlock()
	return bc.ShardState.ActiveValidators
}

func (bc *BlockchainImpl) SelectNextValidator() (string, error) {
	bc.ShardState.Mu.Lock() // Lock needed to read ActiveValidators and read/write NextValidatorIndex safely
	defer bc.ShardState.Mu.Unlock()

	if len(bc.ShardState.ActiveValidators) == 0 {
		// Fallback to Genesis if no active validators and Genesis key exists
		if bc.ShardState.GenesisAccount != nil && bc.ShardState.GenesisAccount.PublicKey() != nil {
			addr, err := bc.ShardState.GenesisAccount.PublicKey().Address()
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
	currentIndex := bc.ShardState.NextValidatorIndex % len(bc.ShardState.ActiveValidators)

	selectedValidator := bc.ShardState.ActiveValidators[currentIndex]
	log.Printf("Selected validator index %d: %s", currentIndex, selectedValidator)

	// Increment index for the next call, wrapping around using modulo
	bc.ShardState.NextValidatorIndex = (currentIndex + 1) // No need for explicit modulo here if we calculate currentIndex each time

	return selectedValidator, nil
}
