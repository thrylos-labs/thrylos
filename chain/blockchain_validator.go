package chain

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/thrylos-labs/thrylos/types"
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
	// First validate the address format
	if !address.Validate(validatorAddress) {
		return nil, fmt.Errorf("invalid validator address format: %s", validatorAddress)
	}

	// Create an address instance by decoding the bech32 string
	prefix, decoded, err := bech32.Decode(validatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to decode validator address %s: %v", validatorAddress, err)
	}

	if prefix != address.AddressPrefix {
		return nil, fmt.Errorf("invalid address prefix: got %s, want %s", prefix, address.AddressPrefix)
	}

	var addr address.Address
	copy(addr[:], decoded)

	// Get the public key using the store's method
	pubKey, err := bc.Blockchain.Database.GetPublicKey(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for validator %s: %v", validatorAddress, err)
	}

	// Convert crypto.PublicKey to bytes
	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for validator %s: %v", validatorAddress, err)
	}

	// Create and unmarshal into MLDSA44 public key
	mldsa44PubKey := new(mldsa44.PublicKey)
	err = mldsa44PubKey.UnmarshalBinary(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to MLDSA44 public key for validator %s: %v", validatorAddress, err)
	}

	return mldsa44PubKey, nil
}

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

	// Check if the validator is active
	if !bc.IsActiveValidator(validatorAddress) {
		log.Printf("Validator %s is not in the active validator list", validatorAddress)
		return nil, "", fmt.Errorf("validator is not active: %s", validatorAddress)
	}

	// Retrieve the private key from the ValidatorKeys store
	privateKey, exists := bc.Blockchain.ValidatorKeys.GetKey(validatorAddress)
	if !exists {
		log.Printf("Failed to retrieve private key for validator %s", validatorAddress)
		return nil, "", fmt.Errorf("failed to retrieve private key for validator %s", validatorAddress)
	}

	// Dereference the pointer to the interface since GetKey returns *crypto.PrivateKey
	cryptoPrivKey := *privateKey

	// Get the public key
	pubKey := cryptoPrivKey.PublicKey()

	// Convert the public key to a bech32 address
	addr, err := pubKey.Address()
	if err != nil {
		log.Printf("Failed to get address from public key for validator %s: %v", validatorAddress, err)
		return nil, "", fmt.Errorf("failed to get address from public key: %v", err)
	}

	bech32Address := addr.String()

	return cryptoPrivKey, bech32Address, nil
}

// // RewardValidator rewards the validator with new tokens
func (bc *BlockchainImpl) RewardValidator(validator string, reward int64) error {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	// Get public key from genesis account
	genesisPublicKey := bc.Blockchain.GenesisAccount.PublicKey()

	// Get address from public key
	genesisAddr, err := genesisPublicKey.Address()
	if err != nil {
		return fmt.Errorf("failed to get genesis address: %v", err)
	}

	// Convert address to string representation
	genesisAddrStr := genesisAddr.String()

	// Deduct reward from Genesis account
	bc.Blockchain.Stakeholders[genesisAddrStr] -= reward
	// Add reward to validator
	bc.Blockchain.Stakeholders[validator] += reward

	return nil
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

func (bc *BlockchainImpl) SimulateValidatorSigning(unsignedBlock *types.Block) (*types.Block, error) {
	log.Printf("Simulating block signing for validator: %s", unsignedBlock.Validator)

	privateKey, bech32Address, err := bc.GetValidatorPrivateKey(unsignedBlock.Validator)
	if err != nil {
		log.Printf("Failed to get validator private key: %v", err)
		return nil, fmt.Errorf("failed to get validator private key: %v", err)
	}

	// Get the private key bytes for hashing
	privateKeyBytes, err := privateKey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Log a hash of the private key for security reasons
	privateKeyHash := sha256.Sum256(privateKeyBytes)
	log.Printf("Private key hash used for signing: %x", privateKeyHash)

	// Update the block's validator address to the Bech32 format
	unsignedBlock.Validator = bech32Address
	log.Printf("Updated block validator to Bech32 address: %s", bech32Address)

	// Generate the block hash
	ComputeBlockHash(unsignedBlock)
	log.Printf("Signing block hash: %x", unsignedBlock.Hash)

	// Get the block bytes for signing
	blockBytes, err := SerializeForSigning(unsignedBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize block for signing: %v", err)
	}

	// Sign the block hash using the private key
	signature := privateKey.Sign(blockBytes)

	// Store the signature directly since it's already a crypto.Signature
	unsignedBlock.Signature = signature

	log.Printf("Block signed successfully for validator: %s", unsignedBlock.Validator)
	log.Printf("Signature: %x", signature.Bytes())

	// Get the public key using the interface method
	publicKey := privateKey.PublicKey()

	// Get the bytes for logging
	publicKeyBytes, err := publicKey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	log.Printf("Public key derived from private key: %x", publicKeyBytes)
	// Validate the bech32 address format
	if !address.Validate(bech32Address) {
		return nil, fmt.Errorf("invalid bech32 address format: %s", bech32Address)
	}

	// Create a new Address from the public key
	validatorAddrPtr, err := publicKey.Address()
	if err != nil {
		return nil, fmt.Errorf("failed to create address from public key: %v", err)
	}

	// Dereference the pointer to get the actual Address value
	validatorAddr := *validatorAddrPtr

	// Verify that this public key is stored correctly using GetPublicKey
	storedPublicKey, err := bc.Blockchain.Database.GetPublicKey(validatorAddr)
	if err != nil {
		log.Printf("Failed to retrieve stored public key for validator %s: %v", bech32Address, err)
	} else {
		storedPublicKeyBytes, err := storedPublicKey.Marshal()
		if err != nil {
			log.Printf("Failed to marshal stored public key for validator %s: %v", bech32Address, err)
		} else {
			log.Printf("Stored public key for validator %s: %x", bech32Address, storedPublicKeyBytes)
			if !bytes.Equal(publicKeyBytes, storedPublicKeyBytes) {
				log.Printf("WARNING: Derived public key does not match stored public key for validator %s", bech32Address)
			}
		}
	}

	return unsignedBlock, nil
}

func (bc *BlockchainImpl) GetActiveValidators() []string {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()
	return bc.Blockchain.ActiveValidators
}
