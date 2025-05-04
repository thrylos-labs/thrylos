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

// FIXME: Does this need to started here?
func (bc *BlockchainImpl) StartPeriodicValidatorUpdate(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			// bc.UpdateActiveValidators(bc.ConsensusManager.GetActiveValidatorCount())
		}
	}()
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

	// Create and unmarshal into MLDSA44 public key
	mldsa44PubKey := new(mldsa44.PublicKey)
	err = mldsa44PubKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		// Log the bytes that failed to unmarshal for debugging
		log.Printf("ERROR: Failed to unmarshal MLDSA44 key for %s. Bytes (hex): %x", validatorAddress, pubKeyBytes)
		return nil, fmt.Errorf("failed to convert DB key to MLDSA44 public key for validator %s: %v", validatorAddress, err)
	}

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
		amount  int64
	}
	validators := make([]validatorStake, 0)

	minValidatorStake := int64(40 * 1e7) // 40 THRYLOS minimum for validators

	for addr, stake := range bc.Blockchain.Stakeholders {
		if stake >= minValidatorStake { // Using fixed minimum validator stake
			validators = append(validators, validatorStake{addr, stake})
		}
	}

	// Sort by stake amount (descending)
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].amount > validators[j].amount
	})

	// Update active validators list
	bc.Blockchain.ActiveValidators = make([]string, 0)
	for i := 0; i < min(count, len(validators)); i++ {
		bc.Blockchain.ActiveValidators = append(bc.Blockchain.ActiveValidators, validators[i].address)
	}
}

func (bc *BlockchainImpl) GetValidatorPrivateKey(validatorAddress string) (crypto.PrivateKey, string, error) {
	log.Printf("Attempting to retrieve private key for validator: %s", validatorAddress)

	// --- Determine Genesis Address ---
	var genesisAddrStr string
	if bc.Blockchain.GenesisAccount != nil && bc.Blockchain.GenesisAccount.PublicKey() != nil {
		addr, err := bc.Blockchain.GenesisAccount.PublicKey().Address()
		if err != nil {
			log.Printf("CRITICAL ERROR: Cannot get Genesis address in GetValidatorPrivateKey: %v", err)
			// Proceed cautiously, but Genesis fallback won't work if this fails.
		} else {
			genesisAddrStr = addr.String()
		}
	} else {
		log.Println("WARN: GenesisAccount or its public key is nil in GetValidatorPrivateKey.")
	}
	// --- End Determine Genesis Address ---

	// --- Check if Active Validator (Only if NOT Genesis) ---
	// If the requested address is the Genesis address, skip the active check.
	if validatorAddress != genesisAddrStr {
		if !bc.IsActiveValidator(validatorAddress) {
			log.Printf("Validator %s is not in the active validator list", validatorAddress)
			// Return error here, as non-genesis validators MUST be active.
			return nil, "", fmt.Errorf("validator is not active: %s", validatorAddress)
		}
		log.Printf("DEBUG: Validator %s is active.", validatorAddress)
	} else {
		log.Printf("DEBUG: Requested validator %s is the Genesis address, skipping active check.", validatorAddress)
	}
	// --- End Check if Active Validator ---

	// --- Retrieve Key from Keystore ---
	// Attempt to retrieve the private key from the ValidatorKeys store first.
	if bc.Blockchain.ValidatorKeys != nil { // Check if Keystore itself is initialized
		privateKeyPtr, exists := bc.Blockchain.ValidatorKeys.GetKey(validatorAddress)
		// --- MODIFIED CHECK: Ensure pointer is not nil AFTER checking exists ---
		if exists && privateKeyPtr != nil {
			log.Printf("DEBUG: Found non-nil private key pointer for %s in ValidatorKeys store.", validatorAddress)
			cryptoPrivKey := *privateKeyPtr // Dereference the pointer safely now

			// Verify the key corresponds to the address (optional but good practice)
			pubKey := cryptoPrivKey.PublicKey()
			if pubKey == nil {
				// Handle case where retrieved key's public key is nil
				log.Printf("ERROR: Retrieved private key for %s has a nil public key.", validatorAddress)
				return nil, "", fmt.Errorf("retrieved key for %s has nil public key", validatorAddress)
			}
			addr, err := pubKey.Address()
			if err != nil {
				log.Printf("ERROR: Failed to get address from retrieved private key for %s: %v", validatorAddress, err)
				return nil, "", fmt.Errorf("error deriving address from retrieved key for %s: %w", validatorAddress, err)
			}
			retrievedAddress := addr.String()
			if retrievedAddress != validatorAddress {
				log.Printf("CRITICAL ERROR: Keystore inconsistency! Key retrieved for %s belongs to %s.", validatorAddress, retrievedAddress)
				return nil, "", fmt.Errorf("keystore key mismatch for address %s", validatorAddress)
			}

			return cryptoPrivKey, retrievedAddress, nil // Return key from keystore
		} else if exists && privateKeyPtr == nil {
			// Log if GetKey returned exists=true but ptr=nil (indicates keystore issue)
			log.Printf("WARN: ValidatorKeys.GetKey returned exists=true but a nil pointer for %s. Keystore may be inconsistent.", validatorAddress)
		} else {
			log.Printf("DEBUG: Key for %s not found in ValidatorKeys store (exists=%v).", validatorAddress, exists)
		}
		// --- END MODIFIED CHECK ---
	} else {
		log.Println("WARN: ValidatorKeys store (bc.Blockchain.ValidatorKeys) is nil.")
	}
	// --- End Retrieve Key from Keystore ---

	// --- Fallback to Genesis Account (Only if requested address IS Genesis) ---
	if validatorAddress == genesisAddrStr && bc.Blockchain.GenesisAccount != nil {
		log.Printf("DEBUG: Key for %s not found in keystore or keystore issue, falling back to GenesisAccount.", validatorAddress)
		// Use the GenesisAccount directly
		genesisPrivKey := bc.Blockchain.GenesisAccount
		// We already derived genesisAddrStr above, use it.
		return genesisPrivKey, genesisAddrStr, nil
	}
	// --- End Fallback to Genesis Account ---

	// --- Key Not Found ---
	// If we reach here, the key wasn't in the keystore, and it wasn't the Genesis fallback case.
	log.Printf("ERROR: Failed to retrieve private key for validator %s. Not in keystore and not Genesis fallback.", validatorAddress)
	return nil, "", fmt.Errorf("failed to retrieve private key for validator %s", validatorAddress)
	// --- End Key Not Found ---
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

// func (bc *BlockchainImpl) SimulateValidatorSigning(unsignedBlock *types.Block) (*types.Block, error) {
// 	if unsignedBlock == nil {
// 		return nil, errors.New("cannot sign nil block")
// 	}
// 	validatorAddress := unsignedBlock.Validator // Get validator ID string from block struct
// 	log.Printf("Simulating block signing for validator: %s", validatorAddress)

// 	// --- Get Private Key ---
// 	privateKey, retrievedAddress, err := bc.GetValidatorPrivateKey(validatorAddress)
// 	if err != nil {
// 		log.Printf("Failed to get validator private key via GetValidatorPrivateKey for %s: %v", validatorAddress, err)
// 		// Fallback for testing: Check if it's the genesis address
// 		log.Printf("Attempting fallback to GenesisAccount...")
// 		if bc.Blockchain.GenesisAccount == nil {
// 			return nil, fmt.Errorf("genesis account key is nil, cannot fallback")
// 		}
// 		genesisPubKey := bc.Blockchain.GenesisAccount.PublicKey()
// 		if genesisPubKey == nil {
// 			return nil, fmt.Errorf("genesis public key is nil, cannot fallback")
// 		}
// 		// --- FIX for multiple-value error ---
// 		genesisAddr, errAddr := genesisPubKey.Address() // Capture both return values
// 		if errAddr != nil {
// 			// Handle error getting genesis address - critical failure
// 			log.Printf("CRITICAL ERROR: Failed to get address from GenesisAccount public key: %v", errAddr)
// 			return nil, fmt.Errorf("failed to derive address from genesis key: %w", errAddr)
// 		}
// 		genesisAddrStr := genesisAddr.String() // Convert address part to string AFTER checking error
// 		// --- END FIX ---

// 		if validatorAddress == genesisAddrStr {
// 			log.Printf("Using GenesisAccount private key as fallback for signing.")
// 			privateKey = bc.Blockchain.GenesisAccount
// 			retrievedAddress = genesisAddrStr // Ensure retrievedAddress is set correctly
// 			// err is already set from the failed GetValidatorPrivateKey attempt, clear it if fallback succeeds
// 			err = nil
// 		} else {
// 			// If it wasn't the genesis address, return the original error
// 			return nil, fmt.Errorf("failed to get private key for non-genesis validator %s: %w", validatorAddress, err)
// 		}
// 	}

// 	// Double check if we successfully got a key
// 	if privateKey == nil {
// 		return nil, fmt.Errorf("could not obtain private key for signing validator %s", validatorAddress)
// 	}
// 	// Optional: Check if retrievedAddress matches validatorAddress if GetValidatorPrivateKey succeeded
// 	if err == nil && retrievedAddress != validatorAddress {
// 		log.Printf("Warning: Retrieved private key address (%s) does not match block validator address (%s)", retrievedAddress, validatorAddress)
// 		// Consider if this should be a hard error
// 	}

// 	// Ensure the block has its hash computed BEFORE signing
// 	ComputeBlockHash(unsignedBlock)
// 	log.Printf("Signing block hash: %x", unsignedBlock.Hash.Bytes())

// 	// --- FIX for unused variable ---
// 	// Remove the unnecessary call to SerializeForSigning here,
// 	// as we are signing the hash bytes directly to match VerifySignedBlock.
// 	/*
// 	   blockBytesForSigning, err := SerializeForSigning(unsignedBlock)
// 	   if err != nil {
// 	       return nil, fmt.Errorf("failed to serialize block for signing: %v", err)
// 	   }
// 	*/
// 	// --- END FIX ---

// 	// Sign the block hash using the private key
// 	signature := privateKey.Sign(unsignedBlock.Hash.Bytes()) // Sign the Hash bytes

// 	// Store the signature directly since it's already a crypto.Signature
// 	unsignedBlock.Signature = signature

// 	log.Printf("Block signed successfully by validator: %s", unsignedBlock.Validator)
// 	log.Printf("Signature: %x", signature.Bytes())

// 	// --- Logging/Verification part (seems okay, keeping as is) ---
// 	publicKey := privateKey.PublicKey()
// 	publicKeyBytes, err := publicKey.Marshal()
// 	if err != nil {
// 		log.Printf("Warning: failed to marshal public key for logging: %v", err)
// 	} else {
// 		log.Printf("Public key derived from private key used for signing: %x", publicKeyBytes)
// 	}
// 	validatorAddrPtrCheck, errAddrCheck := publicKey.Address()
// 	if errAddrCheck == nil {
// 		storedPublicKey, errDb := bc.Blockchain.Database.GetPublicKey(*validatorAddrPtrCheck)
// 		if errDb == nil {
// 			storedPublicKeyBytes, _ := storedPublicKey.Marshal()
// 			if !bytes.Equal(publicKeyBytes, storedPublicKeyBytes) {
// 				log.Printf("WARNING: Derived public key does not match stored public key for validator %s", validatorAddress)
// 			} else {
// 				log.Printf("DEBUG: Derived public key matches stored public key for validator %s", validatorAddress)
// 			}
// 		}
// 	}
// 	// --- End Logging/Verification part ---

// 	return unsignedBlock, nil // Return the now-signed block
// }

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
