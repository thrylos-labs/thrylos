package chain

// const (
// 	keyLen    = 32 // AES-256
// 	nonceSize = 12
// 	saltSize  = 32
// )

// var ErrInvalidKeySize = errors.New("invalid key size")

// func (bc *BlockchainImpl) RegisterPublicKey(pubKey string) error {
// 	// Convert the public key string to bytes, assuming pubKey is base64 encoded
// 	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
// 	if err != nil {
// 		return fmt.Errorf("error decoding public key: %v", err)
// 	}

// 	// Create and parse MLDSA public key from bytes
// 	mldsaPubKey := new(mldsa44.PublicKey)
// 	err = mldsaPubKey.UnmarshalBinary(pubKeyBytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse MLDSA public key: %v", err)
// 	}

// 	// Assuming "publicKeyAddress" should be dynamically determined or correctly provided
// 	return bc.Database.InsertOrUpdateMLDSAPublicKey("publicKeyAddress", mldsaPubKey)
// }

// // // In blockchain.go, within your Blockchain struct definition
// func (bc *BlockchainImpl) RetrievePublicKey(ownerAddress string) (*mldsa44.PublicKey, error) {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	formattedAddress, err := shared.SanitizeAndFormatAddress(ownerAddress)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid address format: %v", err)
// 	}

// 	log.Printf("Attempting to retrieve public key for address: %s", formattedAddress)

// 	// First, check the in-memory map
// 	if pubKey, ok := bc.Blockchain.PublicKeyMap[formattedAddress]; ok {
// 		log.Printf("Public key found in memory for address: %s", formattedAddress)
// 		return pubKey, nil
// 	}

// 	// If not in memory, try the database
// 	pubKeyBytes, err := bc.Database.RetrieveMLDSAPublicKey(formattedAddress)
// 	if err != nil {
// 		log.Printf("Failed to retrieve public key from database for address %s: %v", formattedAddress, err)
// 		return nil, err
// 	}

// 	// Create ML-DSA44 public key from bytes
// 	var publicKey mldsa44.PublicKey
// 	err = publicKey.UnmarshalBinary(pubKeyBytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
// 	}

// 	// Store in memory for future use
// 	bc.Blockchain.PublicKeyMap[formattedAddress] = &publicKey

// 	log.Printf("Successfully retrieved and validated public key for address: %s", formattedAddress)
// 	return &publicKey, nil
// }

// // // // In Blockchain
// func (bc *BlockchainImpl) InsertOrUpdatePublicKey(address string, publicKeyBytes []byte, keyType string) error {
// 	log.Printf("InsertOrUpdatePublicKey called with address: %s, keyType: %s", address, keyType)

// 	if len(publicKeyBytes) == 0 {
// 		return fmt.Errorf("empty public key bytes provided")
// 	}
// 	log.Printf("PublicKey bytes: %x", publicKeyBytes)

// 	switch keyType {
// 	case "MLDSA":
// 		// Parse the bytes into an MLDSA public key
// 		pubKey := new(mldsa44.PublicKey)
// 		err := pubKey.UnmarshalBinary(publicKeyBytes)
// 		if err != nil {
// 			log.Printf("Failed to parse MLDSA public key for address %s: %v", address, err)
// 			return fmt.Errorf("failed to parse MLDSA public key: %v", err)
// 		}

// 		// Store the parsed key
// 		err = bc.Database.InsertOrUpdateMLDSAPublicKey(address, pubKey)
// 		if err != nil {
// 			log.Printf("Failed to store MLDSA public key for address %s: %v", address, err)
// 			return fmt.Errorf("failed to store MLDSA public key: %v", err)
// 		}

// 		log.Printf("Successfully stored MLDSA public key for address %s", address)
// 		return nil
// 	default:
// 		return fmt.Errorf("unsupported key type: %s", keyType)
// 	}
// }

// func (bc *BlockchainImpl) EnsureTestValidatorRegistered(address string, publicKey mldsa44.PublicKey) error {
// 	// Check if the validator is already registered
// 	_, err := bc.RetrievePublicKey(address)
// 	if err == nil {
// 		// Validator is already registered
// 		return nil
// 	}

// 	// Serialize the public key to bytes
// 	publicKeyBytes := publicKey.Bytes()

// 	// Encode the public key to Base64
// 	pubKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

// 	// Register the validator
// 	err = bc.RegisterValidator(address, pubKeyBase64, true)
// 	if err != nil {
// 		return fmt.Errorf("failed to register test validator: %v", err)
// 	}

// 	log.Printf("Registered test validator: %s", address)
// 	return nil
// }

// func deriveKey(password []byte, salt []byte) ([]byte, error) {
// 	return scrypt.Key(password, salt, 32768, 8, 1, keyLen)
// }

// func encryptPrivateKey(privKey *mldsa44.PrivateKey) ([]byte, error) {
// 	// Convert ML-DSA44 private key to bytes
// 	privKeyBytes, err := privKey.MarshalBinary()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal private key: %v", err)
// 	}

// 	salt := make([]byte, saltSize)
// 	if _, err := rand.Read(salt); err != nil {
// 		return nil, err
// 	}

// 	block, err := aes.NewCipher(salt)
// 	if err != nil {
// 		return nil, err
// 	}

// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}

// 	nonce := make([]byte, gcm.NonceSize())
// 	if _, err := rand.Read(nonce); err != nil {
// 		return nil, err
// 	}

// 	ciphertext := gcm.Seal(nil, nonce, privKeyBytes, nil)
// 	return append(append(salt, nonce...), ciphertext...), nil
// }

// func decryptPrivateKey(encryptedKey []byte) (*mldsa44.PrivateKey, error) {
// 	if len(encryptedKey) < saltSize+nonceSize+1 {
// 		return nil, ErrInvalidKeySize
// 	}

// 	salt := encryptedKey[:saltSize]
// 	nonce := encryptedKey[saltSize : saltSize+nonceSize]
// 	ciphertext := encryptedKey[saltSize+nonceSize:]

// 	block, err := aes.NewCipher(salt)
// 	if err != nil {
// 		return nil, err
// 	}

// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}

// 	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Convert bytes back to ML-DSA44 private key
// 	var privKey mldsa44.PrivateKey
// 	err = privKey.UnmarshalBinary(plaintext)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
// 	}

// 	return &privKey, nil
// }

// func (bc *BlockchainImpl) CheckValidatorKeyConsistency() error {
// 	log.Println("Checking validator key consistency")

// 	allPublicKeys, err := bc.Database.GetAllValidatorPublicKeys()
// 	if err != nil {
// 		return fmt.Errorf("failed to retrieve all validator public keys: %v", err)
// 	}

// 	log.Printf("Total stored validator public keys: %d", len(allPublicKeys))
// 	log.Printf("Total active validators: %d", len(bc.ActiveValidators))

// 	for address, storedPubKey := range allPublicKeys {
// 		log.Printf("Checking consistency for validator: %s", address)

// 		// Convert stored public key to bytes for logging
// 		storedPubKeyBytes, err := storedPubKey.MarshalBinary()
// 		if err != nil {
// 			log.Printf("Failed to marshal stored public key for validator %s: %v", address, err)
// 			continue
// 		}
// 		log.Printf("Stored public key for %s: %x", address, storedPubKeyBytes)

// 		if bc.IsActiveValidator(address) {
// 			log.Printf("Validator %s is active", address)

// 			privateKey, bech32Address, err := bc.GetValidatorPrivateKey(address)
// 			if err != nil {
// 				log.Printf("Failed to retrieve private key for validator %s: %v", address, err)
// 				continue
// 			}

// 			log.Printf("Retrieved private key for %s, Bech32 address: %s", address, bech32Address)

// 			// Fixed: Use pointer type for the type assertion
// 			derivedPublicKey := privateKey.Public().(*mldsa44.PublicKey)

// 			// Convert both keys to bytes for comparison
// 			derivedPubKeyBytes, err := derivedPublicKey.MarshalBinary()
// 			if err != nil {
// 				return fmt.Errorf("failed to marshal derived public key for validator %s: %v", address, err)
// 			}

// 			storedPubKeyBytes, err := storedPubKey.MarshalBinary()
// 			if err != nil {
// 				return fmt.Errorf("failed to marshal stored public key for validator %s: %v", address, err)
// 			}

// 			log.Printf("Derived public key for %s: %x", address, derivedPubKeyBytes)

// 			if !bytes.Equal(storedPubKeyBytes, derivedPubKeyBytes) {
// 				log.Printf("Key mismatch for validator %s (Bech32: %s):", address, bech32Address)
// 				log.Printf("  Stored public key:  %x", storedPubKeyBytes)
// 				log.Printf("  Derived public key: %x", derivedPubKeyBytes)
// 				return fmt.Errorf("key mismatch for active validator %s (Bech32: %s): stored public key does not match derived public key",
// 					address, bech32Address)
// 			}

// 			log.Printf("Keys consistent for active validator %s", address)
// 		} else {
// 			log.Printf("Validator %s is not active", address)
// 		}
// 	}

// 	for _, activeAddress := range bc.ActiveValidators {
// 		if _, exists := allPublicKeys[activeAddress]; !exists {
// 			log.Printf("Active validator %s does not have a stored public key", activeAddress)
// 			return fmt.Errorf("active validator %s does not have a stored public key", activeAddress)
// 		}
// 	}

// 	log.Println("Validator key consistency check completed")
// 	return nil
// }

// Load all Validator public keys into Memory
// func (bc *BlockchainImpl) LoadAllValidatorPublicKeys() error {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	log.Println("Loading all validator public keys")

// 	for address := range bc.Stakeholders {
// 		log.Printf("Attempting to load public key for stakeholder: %s", address)
// 		pubKeyBytes, err := bc.Database.RetrieveValidatorPublicKey(address)
// 		if err != nil {
// 			log.Printf("Failed to load public key for stakeholder %s: %v", address, err)
// 			continue
// 		}

// 		if len(pubKeyBytes) > 0 {
// 			// Create a new PublicKey instance
// 			pubKey := new(mldsa44.PublicKey)
// 			// Parse the bytes into the public key
// 			err = pubKey.UnmarshalBinary(pubKeyBytes)
// 			if err != nil {
// 				log.Printf("Failed to parse public key for stakeholder %s: %v", address, err)
// 				continue
// 			}

// 			// Store the pointer directly
// 			bc.PublicKeyMap[address] = pubKey
// 			log.Printf("Loaded public key for validator: %s", address)
// 		}
// 	}

// 	log.Printf("Loaded public keys for %d validators", len(bc.PublicKeyMap))
// 	return nil
// }
