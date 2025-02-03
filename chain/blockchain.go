package chain

// // other necessary imports

// NewTransaction creates a new transaction
// type Stakeholder struct {
// 	Address string
// 	Stake   int
// }

// type BlockchainConfig struct {
// 	DataDir           string
// 	AESKey            []byte
// 	GenesisAccount    string
// 	TestMode          bool
// 	DisableBackground bool
// 	StateManager      *shared.StateManager
// }

// const (
// 	keyLen    = 32 // AES-256
// 	nonceSize = 12
// 	saltSize  = 32
// )

// var ErrInvalidKeySize = errors.New("invalid key size")

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

// type BlockchainImpl struct {
// 	*shared.Blockchain
// }

// // // GetMinStakeForValidator returns the current minimum stake required for a validator
// func (bc *BlockchainImpl) GetMinStakeForValidator() *big.Int {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()
// 	return new(big.Int).Set(bc.MinStakeForValidator) // Return a copy to prevent modification
// }

// // // You might also want to add a setter method if you need to update this value dynamically
// func (bc *BlockchainImpl) SetMinStakeForValidator(newMinStake *big.Int) {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()
// 	bc.MinStakeForValidator = new(big.Int).Set(newMinStake)
// }

// func ConvertToBech32Address(address string) (string, error) {
// 	// Check if the address is already in Bech32 format
// 	if strings.HasPrefix(address, "tl1") {
// 		return address, nil
// 	}

// 	// Try to decode the address as hexadecimal
// 	addressBytes, err := hex.DecodeString(address)
// 	if err == nil {
// 		// Take the first 20 bytes (40 characters of the hex string)
// 		// This is similar to how Ethereum addresses are derived from public keys
// 		if len(addressBytes) > 20 {
// 			addressBytes = addressBytes[:20]
// 		}

// 		// Convert to 5-bit groups for Bech32 encoding
// 		converted, err := bech32.ConvertBits(addressBytes, 8, 5, true)
// 		if err != nil {
// 			return "", fmt.Errorf("failed to convert bits: %v", err)
// 		}

// 		// Encode to Bech32
// 		bech32Address, err := bech32.Encode("tl1", converted)
// 		if err != nil {
// 			return "", fmt.Errorf("failed to encode address to Bech32: %v", err)
// 		}

// 		return bech32Address, nil
// 	}

// 	// If the address is not in hexadecimal format, try to use it directly
// 	return address, nil
// }

// // // NewBlockchain initializes and returns a new instance of a Blockchain. It sets up the necessary
// // // infrastructure, including the genesis block and the database connection for persisting the blockchain state.
// func NewBlockchainWithConfig(config *BlockchainConfig) (*BlockchainImpl, shared.Store, error) {
// 	// Initialize the database
// 	db, err := store.NewDatabase(config.DataDir)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
// 	}
// 	bdb := store.NewBlockchainDB(db, config.AESKey)
// 	log.Println("BlockchainDB created")

// 	// Create the genesis block
// 	genesis := NewGenesisBlock()
// 	log.Println("Genesis block created")

// 	// Initialize the map for public keys
// 	publicKeyMap := make(map[string]*mldsa44.PublicKey)

// 	// Initialize Stakeholders map with the genesis account
// 	totalSupplyNano := utils.ThrylosToNano()

// 	log.Printf("Initializing genesis account with total supply: %.2f THR", utils.NanoToThrylos(totalSupplyNano))

// 	// Convert the genesis account address to Bech32 format
// 	bech32GenesisAccount, err := ConvertToBech32Address(config.GenesisAccount)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to convert genesis account to Bech32: %v", err)
// 	}

// 	// Use bech32GenesisAccount instead of genesisAccount from here on
// 	stakeholdersMap := make(map[string]int64)
// 	stakeholdersMap[bech32GenesisAccount] = totalSupplyNano // Genesis holds total supply including staking reserve

// 	log.Printf("Initializing genesis account: %s", config.GenesisAccount)

// 	// Generate a new key pair for the genesis account
// 	log.Println("Generating key pair for genesis account")
// 	genesisPublicKey, genesisPrivateKey, err := mldsa44.GenerateKey(nil)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to generate genesis account key pair: %v", err)
// 	}
// 	log.Println("Genesis account key pair generated successfully")

// 	log.Println("Storing public key for genesis account")
// 	err = db.Blockchain.StoreValidatorMLDSAPublicKey(bech32GenesisAccount, genesisPublicKey)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to store genesis account public key: %v", err)
// 	}
// 	log.Println("Genesis account public key stored successfully")

// 	// Create genesis transaction
// 	// Create genesis transaction
// 	genesisTx := &thrylos.Transaction{
// 		Id:        "genesis_tx_" + bech32GenesisAccount,
// 		Timestamp: time.Now().Unix(),
// 		Outputs: []*thrylos.UTXO{{
// 			OwnerAddress: config.GenesisAccount,
// 			Amount:       totalSupplyNano,
// 		}},
// 		Signature:       []byte("genesis_signature"), // Keep as is since it's genesis
// 		SenderPublicKey: nil,                         // No need for genesis
// 	}

// 	// Initialize UTXO map with the genesis transaction
// 	utxoMap := make(map[string][]*thrylos.UTXO)
// 	utxoKey := fmt.Sprintf("%s:%d", genesisTx.Id, 0)
// 	utxoMap[utxoKey] = []*thrylos.UTXO{genesisTx.Outputs[0]}

// 	genesis.Transactions = []*thrylos.Transaction{genesisTx}

// 	stateNetwork := shared.NewDefaultNetwork()
// 	stateManager := state.NewStateManager(stateNetwork, 4)

// 	blockchain := &BlockchainImpl{
// 		Blocks:              []*shared.Block{genesis},
// 		Genesis:             genesis,
// 		Stakeholders:        stakeholdersMap,
// 		Database:            bdb,
// 		PublicKeyMap:        publicKeyMap,
// 		UTXOs:               utxoMap,
// 		Forks:               make([]*shared.Fork, 0),
// 		GenesisAccount:      bech32GenesisAccount,
// 		PendingTransactions: make([]*thrylos.Transaction, 0),
// 		ActiveValidators:    make([]string, 0),
// 		StateNetwork:        stateNetwork,
// 		ValidatorKeys:       validators.NewValidatorKeyStore(),
// 		TestMode:            config.TestMode,
// 		StateManager:        stateManager,
// 	}

// 	// Now store the private key for the genesis account
// 	log.Println("Storing private key for genesis account")
// 	blockchain.ValidatorKeys.StoreKey(bech32GenesisAccount, genesisPrivateKey)

// 	// Verify that the key was stored correctly
// 	// Verify that the key was stored correctly
// 	storedKey, exists := blockchain.ValidatorKeys.GetKey(bech32GenesisAccount)
// 	if !exists {
// 		return nil, nil, fmt.Errorf("failed to store genesis account private key: key not found after storage")
// 	}

// 	// Marshal both keys to bytes for comparison
// 	storedKeyBytes, err := storedKey.MarshalBinary()
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to marshal stored private key: %v", err)
// 	}

// 	genesisPrivateKeyBytes, err := genesisPrivateKey.MarshalBinary()
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to marshal genesis private key: %v", err)
// 	}

// 	// Compare the marshaled bytes
// 	if !bytes.Equal(storedKeyBytes, genesisPrivateKeyBytes) {
// 		return nil, nil, fmt.Errorf("failed to store genesis account private key: stored key does not match original")
// 	}
// 	log.Println("Genesis account private key stored and verified successfully")

// 	// Add the genesis public key to the publicKeyMap
// 	blockchain.PublicKeyMap[bech32GenesisAccount] = genesisPublicKey
// 	log.Println("Genesis account public key added to publicKeyMap")

// 	// When logging the genesis account
// 	log.Printf("Genesis account %s initialized with total supply: %d", bech32GenesisAccount, totalSupplyNano)

// 	// Set the minimum stake for validators
// 	//FIXME: we need to harmonise the minimum stake amount in one service
// 	blockchain.MinStakeForValidator = big.NewInt(staking.MinimumStakeAmount)

// 	// Initialize ConsensusManager which provides sufficient consensus management
// 	blockchain.ConsensusManager = consensus.NewConsensusManager(blockchain)

// 	log.Println("Generating and storing validator keys")
// 	validatorAddresses, err := blockchain.GenerateAndStoreValidatorKeys(2)
// 	if err != nil {
// 		log.Printf("Warning: Failed to generate validator keys: %v", err)
// 		return nil, nil, fmt.Errorf("failed to generate validator keys: %v", err)
// 	}
// 	log.Println("Validator keys generated and stored")

// 	// Add generated validators to ActiveValidators list
// 	blockchain.ActiveValidators = append(blockchain.ActiveValidators, validatorAddresses...)
// 	log.Printf("Added %d validators to ActiveValidators list", len(validatorAddresses))

// 	// Add genesis account as a validator if it's not already included
// 	if !contains(blockchain.ActiveValidators, bech32GenesisAccount) {
// 		blockchain.ActiveValidators = append(blockchain.ActiveValidators, bech32GenesisAccount)
// 		log.Printf("Added genesis account to ActiveValidators list")
// 	}

// 	log.Printf("Total ActiveValidators: %d", len(blockchain.ActiveValidators))

// 	// Add this check
// 	log.Println("Verifying stored validator keys")
// 	keys, err := db.Blockchain.GetAllValidatorPublicKeys()
// 	if err != nil {
// 		log.Printf("Failed to retrieve all validator public keys: %v", err)
// 		return nil, nil, fmt.Errorf("failed to verify stored validator keys: %v", err)
// 	}
// 	log.Printf("Retrieved %d validator public keys", len(keys))

// 	log.Println("Loading all validator public keys")
// 	err = blockchain.LoadAllValidatorPublicKeys()
// 	if err != nil {
// 		log.Printf("Warning: Failed to load all validator public keys: %v", err)
// 	}
// 	log.Println("Validator public keys loaded")

// 	log.Println("Checking validator key consistency")
// 	blockchain.CheckValidatorKeyConsistency()
// 	log.Println("Validator key consistency check completed")

// 	// Start periodic validator update in a separate goroutine
// 	go func() {
// 		log.Println("Starting periodic validator update")
// 		blockchain.StartPeriodicValidatorUpdate(15 * time.Minute)
// 	}()

// 	// Serialize and store the genesis block
// 	var buf bytes.Buffer
// 	encoder := gob.NewEncoder(&buf)
// 	if err := encoder.Encode(genesis); err != nil {
// 		return nil, nil, fmt.Errorf("failed to serialize genesis block: %v", err)
// 	}
// 	if err := db.Blockchain.InsertBlock(buf.Bytes(), 0); err != nil {
// 		return nil, nil, fmt.Errorf("failed to add genesis block to the database: %v", err)
// 	}

// 	log.Printf("Genesis account %s initialized with total supply: %d", config.GenesisAccount, totalSupplyNano)

// 	log.Println("NewBlockchain initialization completed successfully")

// 	// Add after state sync loop start and before return
// 	blockchain.StateManager.StartStateSyncLoop()
// 	log.Println("State synchronization loop started")

// 	// Add shutdown handler
// 	go func() {
// 		c := make(chan os.Signal, 1)
// 		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
// 		<-c
// 		log.Println("Stopping state synchronization...")
// 		blockchain.StateManager.StopStateSyncLoop()
// 	}()

// 	// Initialize staking service with proper configuration
// 	log.Println("Initialize staking service...")
// 	blockchain.StakingService = NewStakingService(blockchain)

// 	log.Printf("Staking service initialized with:")
// 	log.Printf("- Minimum stake: %d THRYLOS", blockchain.StakingService.pool.MinStakeAmount/1e7)
// 	log.Printf("- Fixed yearly reward: 4.8M THRYLOS")
// 	log.Printf("- Current total supply: 120M THRYLOS")

// 	log.Println("Initializing transaction propagator...")
// 	blockchain.TransactionPropagator = NewTransactionPropagator(blockchain)
// 	log.Println("Transaction propagator initialized successfully")

// 	// Modify background process initialization based on DisableBackground flag
// 	if !config.DisableBackground {
// 		go func() {
// 			log.Println("Starting daily staking reward distribution process")
// 			for {
// 				if err := blockchain.StakingService.DistributeRewards(); err != nil {
// 					log.Printf("Error distributing staking rewards: %v", err)
// 				}
// 				// Sleep for 1 hour instead of 1 minute since we only need to check daily
// 				// This reduces unnecessary checks while ensuring we don't miss the 24-hour mark
// 				time.Sleep(time.Hour)
// 			}
// 		}()

// 		// Start periodic validator update in a separate goroutine
// 		go func() {
// 			log.Println("Starting periodic validator update")
// 			blockchain.StartPeriodicValidatorUpdate(15 * time.Minute)
// 		}()

// 		// Start state synchronization loop
// 		blockchain.StateManager.StartStateSyncLoop()
// 		log.Println("State synchronization loop started")

// 		// Add shutdown handler
// 		go func() {
// 			c := make(chan os.Signal, 1)
// 			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
// 			<-c
// 			log.Println("Stopping state synchronization...")
// 			blockchain.StateManager.StopStateSyncLoop()
// 		}()

// 		// Start block creation routine
// 		go func() {
// 			log.Println("Starting block creation process")
// 			ticker := time.NewTicker(10 * time.Second) // Or whatever interval is appropriate
// 			defer ticker.Stop()

// 			for {
// 				select {
// 				case <-ticker.C:
// 					// Check if there are pending transactions
// 					if len(blockchain.PendingTransactions) > 0 {
// 						block, err := blockchain.CreateNextBlock()
// 						if err != nil {
// 							log.Printf("Failed to create new block: %v", err)
// 							continue
// 						}
// 						log.Printf("Successfully created new block %d with %d transactions",
// 							block.Index, len(block.Transactions))

// 					}
// 				}
// 			}
// 		}()
// 	} else {
// 		// In test mode, log that background processes are disabled
// 		log.Println("Background processes disabled for testing")
// 	}

// 	log.Println("NewBlockchain initialization completed successfully")
// 	return blockchain, bdb, nil
// }

// // // // FIXME: The total supply is not correct, it needs to be improved
// func (bc *BlockchainImpl) GetTotalSupply() int64 {
// 	totalSupply := int64(0)
// 	for _, balance := range bc.Stakeholders {
// 		totalSupply += balance
// 	}
// 	return totalSupply
// }

// func (bc *BlockchainImpl) GetEffectiveInflationRate() float64 {
// 	currentTotalSupply := utils.NanoToThrylos(bc.GetTotalSupply())
// 	// Calculate effective rate (will decrease as total supply grows)
// 	effectiveRate := (utils.NanoToThrylos(config.AnnualStakeReward) / currentTotalSupply) * 100
// 	return effectiveRate
// }

// func contains(slice []string, item string) bool {
// 	for _, a := range slice {
// 		if a == item {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (bc *BlockchainImpl) getActiveNodeCount() int {
// 	// This is a placeholder. In a real implementation, you would track active nodes.
// 	// For now, we'll return a constant value.
// 	return 50
// }

// // Example usage function
// func (bc *BlockchainImpl) CreateNextBlock(nodes ...*node.Node) (*shared.Block, error) {
// 	var node *node.Node
// 	if len(nodes) > 0 {
// 		node = nodes[0]
// 	}

// 	selector := selection.NewValidatorSelector(bc, node)

// 	validator, err := selector.validator.SelectNextValidator()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to select validator: %v", err)
// 	}

// 	return bc.CreateBlockFromPendingTransactions(validator)
// }

// func (bc *BlockchainImpl) calculateAverageLatency() time.Duration {
// 	// This is a placeholder. In a real implementation, you would measure actual network latency.
// 	// For now, we'll return a constant value.
// 	return 200 * time.Millisecond
// }

// // FIXME: Does this need to started here?
// func (bc *BlockchainImpl) StartPeriodicValidatorUpdate(interval time.Duration) {
// 	ticker := time.NewTicker(interval)
// 	go func() {
// 		for range ticker.C {
// 			bc.UpdateActiveValidators(bc.ConsensusManager.GetActiveValidatorCount())
// 		}
// 	}()
// }

// // // When reading or processing transactions that have been deserialized from Protobuf, you'll use ConvertProtoUTXOToShared to convert the Protobuf-generated UTXOs back into the format your application uses internally.

// // // ConvertProtoUTXOToShared converts a Protobuf-generated UTXO to your shared UTXO type.
// func ConvertProtoUTXOToShared(protoUTXO *thrylos.UTXO) shared.UTXO {
// 	return shared.UTXO{
// 		ID:            protoUTXO.GetTransactionId(), // Assuming you have corresponding fields
// 		TransactionID: protoUTXO.GetTransactionId(),
// 		Index:         int(protoUTXO.GetIndex()), // Convert from int32 to int if necessary
// 		OwnerAddress:  protoUTXO.GetOwnerAddress(),
// 		Amount:        int64(protoUTXO.GetAmount()), // Convert from int64 to int if necessary
// 	}
// }

// func (bc *BlockchainImpl) Status() string {
// 	// Example status: return the number of blocks in the blockchain
// 	return fmt.Sprintf("Current blockchain length: %d blocks", len(bc.Blocks))
// }

// func (bc *BlockchainImpl) CreateInitialWalletUTXO(address string, initialBalance int64) error {
// 	utxo := shared.UTXO{
// 		OwnerAddress:  address,
// 		Amount:        initialBalance,
// 		TransactionID: fmt.Sprintf("genesis-%s", address),
// 		IsSpent:       false,
// 		Index:         0, // Use 0 for initial UTXO
// 	}

// 	return bc.Database.AddUTXO(utxo)
// }

// func (bc *BlockchainImpl) GetUTXOsForAddress(address string) ([]shared.UTXO, error) {
// 	log.Printf("Fetching UTXOs for address: %s", address)
// 	utxos, err := bc.Database.GetUTXOsForAddress(address)
// 	if err != nil {
// 		log.Printf("Failed to fetch UTXOs from database: %s", err)
// 		return nil, err
// 	}
// 	log.Printf("Retrieved %d UTXOs for address %s", len(utxos), address)
// 	return utxos, nil
// }

// func (bc *BlockchainImpl) GetAllUTXOs() (map[string][]shared.UTXO, error) {
// 	return bc.Database.GetAllUTXOs()
// }

// func (bc *BlockchainImpl) GetUTXOsForUser(address string) ([]shared.UTXO, error) {
// 	return bc.Database.GetUTXOsForUser(address)
// }

// // // Always deals with nanoTHRYLOS as int64
// func (bc *BlockchainImpl) GetBalance(address string) (int64, error) {
// 	var balance int64 = 0
// 	utxos, err := bc.Database.GetUTXOsForAddress(address)
// 	if err != nil {
// 		return 0, err
// 	}

// 	for _, utxo := range utxos {
// 		if !utxo.IsSpent {
// 			balance += utxo.Amount
// 		}
// 	}
// 	return balance, nil
// }

// // // ConvertToThrylos converts nanoTHRYLOS to THRYLOS
// func ConvertToThrylos(nanoThrylos decimal.Decimal) decimal.Decimal {
// 	return nanoThrylos.Div(decimal.NewFromInt(1e7))
// }

// // // ConvertToNanoThrylos converts THRYLOS to nanoTHRYLOS
// func ConvertToNanoThrylos(thrylos decimal.Decimal) decimal.Decimal {
// 	return thrylos.Mul(decimal.NewFromInt(1e7))
// }

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
// 	if pubKey, ok := bc.PublicKeyMap[formattedAddress]; ok {
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
// 	bc.PublicKeyMap[formattedAddress] = &publicKey

// 	log.Printf("Successfully retrieved and validated public key for address: %s", formattedAddress)
// 	return &publicKey, nil
// }

// func (bc *BlockchainImpl) ProcessPendingTransactionsWithBatch(validator string, batch []*thrylos.Transaction) (*shared.Block, error) {
// 	// Similar to ProcessPendingTransactions but works with the provided batch
// 	return bc.ProcessPendingTransactions(validator)
// }

// // Load all Validator public keys into Memory
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

// func (bc *BlockchainImpl) GetValidatorPublicKey(validatorAddress string) (*mldsa44.PublicKey, error) {
// 	// Retrieve the public key from storage
// 	storedPubKey, err := bc.Database.RetrieveValidatorPublicKey(validatorAddress)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to retrieve public key for validator %s: %v", validatorAddress, err)
// 	}

// 	// Create a new MLDSA44 public key
// 	publicKey := new(mldsa44.PublicKey)

// 	// Unmarshal the stored bytes into the public key
// 	err = publicKey.UnmarshalBinary(storedPubKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal public key for validator %s: %v", validatorAddress, err)
// 	}

// 	return publicKey, nil
// }

// // // CreateBlock generates a new block with the given transactions, validator, previous hash, and timestamp.
// // // This method encapsulates the logic for building a block to be added to the blockchain.
// func (bc *BlockchainImpl) CreateUnsignedBlock(transactions []*thrylos.Transaction, validator string) (shared.Block, error) {
// 	prevBlock := bc.Blocks[len(bc.Blocks)-1]
// 	newBlock := &shared.Block{
// 		Index:        int32(len(bc.Blocks)),
// 		Timestamp:    time.Now().Unix(),
// 		Transactions: shartransactions,
// 		Validator:    validator,
// 		PrevHash:     prevBlock.Hash,
// 		// Hash and Signature fields are left empty
// 	}

// 	// Initialize Verkle tree before computing hash
// 	if err := InitializeVerkleTree(); err != nil {
// 		return nil, fmt.Errorf("failed to initialize Verkle tree: %v", err)
// 	}

// 	// Compute the hash
// 	newBlock.Hash = newBlock.ComputeBlockHash()

// 	return newBlock, nil
// }

// func (bc *BlockchainImpl) VerifySignedBlock(signedBlock *Block) error {
// 	// Verify the block's hash
// 	computedHash := signedBlock.ComputeHash()
// 	if !bytes.Equal(computedHash, signedBlock.Hash) {
// 		log.Printf("Block hash mismatch. Computed: %x, Block: %x", computedHash, signedBlock.Hash)
// 		return errors.New("invalid block hash")
// 	}

// 	publicKey, err := bc.GetValidatorPublicKey(signedBlock.Validator)
// 	if err != nil {
// 		log.Printf("Failed to get validator public key: %v", err)
// 		return fmt.Errorf("failed to get validator public key: %v", err)
// 	}

// 	pubKeyBytes, err := publicKey.MarshalBinary()
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal public key for logging: %v", err)
// 	}
// 	log.Printf("Retrieved public key for verification: %x", pubKeyBytes)

// 	// Also try to retrieve the public key directly from the database
// 	storedPubKeyBytes, err := bc.Database.RetrieveValidatorPublicKey(signedBlock.Validator)
// 	if err != nil {
// 		log.Printf("Failed to retrieve stored public key for validator %s: %v", signedBlock.Validator, err)
// 	} else {
// 		log.Printf("Stored public key for validator %s: %x", signedBlock.Validator, storedPubKeyBytes)

// 		// Create a new public key to unmarshal the stored bytes
// 		storedPublicKey := new(mldsa44.PublicKey)
// 		err = storedPublicKey.UnmarshalBinary(storedPubKeyBytes)
// 		if err != nil {
// 			log.Printf("Failed to unmarshal stored public key: %v", err)
// 		} else {
// 			// Compare the marshaled forms of both keys
// 			currentKeyBytes, _ := publicKey.MarshalBinary()
// 			storedKeyBytes, _ := storedPublicKey.MarshalBinary()
// 			if !bytes.Equal(currentKeyBytes, storedKeyBytes) {
// 				log.Printf("WARNING: Retrieved public key does not match stored public key for validator %s", signedBlock.Validator)
// 			}
// 		}
// 	}

// 	// Verify the signature using MLDSA44
// 	// Note: passing nil as the context parameter as it's not used in the block signing
// 	if !mldsa44.Verify(publicKey, signedBlock.Hash, nil, signedBlock.Signature) {
// 		log.Printf("Signature verification failed. Validator: %s, Block Hash: %x, Signature: %x",
// 			signedBlock.Validator, signedBlock.Hash, signedBlock.Signature)
// 		return errors.New("invalid block signature")
// 	}

// 	log.Printf("Block signature verified successfully for validator: %s", signedBlock.Validator)
// 	return nil
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

// // // Helper function to efficiently check salt uniqueness in all blocks
// func (bc *BlockchainImpl) checkSaltInBlocks(salt []byte) bool {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	// Create an efficient lookup for pending transaction salts
// 	pendingSalts := make(map[string]bool)
// 	for _, tx := range bc.PendingTransactions {
// 		pendingSalts[string(tx.Salt)] = true
// 	}

// 	// Check pending transactions first (faster in-memory check)
// 	if pendingSalts[string(salt)] {
// 		return true
// 	}

// 	// Check confirmed blocks
// 	for _, block := range bc.Blocks {
// 		for _, tx := range block.Transactions {
// 			if bytes.Equal(tx.Salt, salt) {
// 				return true
// 			}
// 		}
// 	}

// 	return false
// }

// // // Helper function to verify transaction uniqueness using salt
// func verifyTransactionUniqueness(tx *thrylos.Transaction, blockchain *BlockchainImpl) error {
// 	if tx == nil {
// 		return fmt.Errorf("nil transaction")
// 	}
// 	if len(tx.Salt) == 0 {
// 		return fmt.Errorf("empty salt")
// 	}
// 	if len(tx.Salt) != 32 {
// 		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
// 	}

// 	// Use the efficient helper function to check salt uniqueness
// 	if blockchain.checkSaltInBlocks(tx.Salt) {
// 		return fmt.Errorf("duplicate salt detected: transaction replay attempt")
// 	}

// 	return nil
// }

// func (bc *BlockchainImpl) SignBlock(block *shared.Block, validatorAddress string) ([]byte, error) {
// 	privateKey, bech32Address, err := bc.GetValidatorPrivateKey(validatorAddress)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get validator private key: %v", err)
// 	}

// 	// The Bech32 address is already returned by GetValidatorPrivateKey, so we don't need to convert it again
// 	block.Validator = bech32Address

// 	blockData, err := block.SerializeForSigning()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to serialize block for signing: %v", err)
// 	}

// 	signature, err := privateKey.Sign(nil, blockData, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to sign block: %v", err)
// 	}
// 	return signature, nil
// }

// func (bc *BlockchainImpl) SlashMaliciousValidator(validatorAddress string, slashAmount int64) {
// 	if _, ok := bc.Stakeholders[validatorAddress]; ok {
// 		// Deduct the slashAmount from the stake
// 		bc.Stakeholders[validatorAddress] -= slashAmount
// 		if bc.Stakeholders[validatorAddress] <= 0 {
// 			// Remove validator if their stake goes to zero or negative
// 			delete(bc.Stakeholders, validatorAddress)
// 		}
// 	}
// }

// func (bc *BlockchainImpl) IsSlashed(validator string) bool {
// 	// Check if validator is in slashed state
// 	if stake, exists := bc.Stakeholders[validator]; exists {
// 		return stake < bc.MinStakeForValidator.Int64() // Validator is slashed if below min stake
// 	}
// 	return false
// }

// // not sure if needed
// func (bc *BlockchainImpl) GetChainID() string {
// 	return "tl1" // Mainnet (adjust as per your chain)
// }

// func (bc *BlockchainImpl) ResolveForks() {
// 	var longestFork *Fork
// 	longestLength := len(bc.Blocks)
// 	for _, fork := range bc.Forks {
// 		if len(fork.Blocks)+fork.Index > longestLength {
// 			longestLength = len(fork.Blocks) + fork.Index
// 			longestFork = fork
// 		}
// 	}
// 	if longestFork != nil {
// 		// Switch to the longest fork
// 		bc.Blocks = append(bc.Blocks[:longestFork.Index], longestFork.Blocks...)
// 	}
// 	// Clear forks as the longest chain is now the main chain
// 	bc.Forks = nil
// }

// // // In Blockchain
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

// func (bc *BlockchainImpl) validateBlockTransactionSalts(block *shared.Block) error {
// 	seenSalts := make(map[string]bool)

// 	for _, tx := range block.Transactions {
// 		saltStr := string(tx.Salt)
// 		if seenSalts[saltStr] {
// 			return fmt.Errorf("duplicate salt found in block transactions")
// 		}
// 		seenSalts[saltStr] = true

// 		// Verify each transaction's salt
// 		if err := verifyTransactionUniqueness(tx, bc); err != nil {
// 			return fmt.Errorf("invalid transaction salt: %v", err)
// 		}
// 	}
// 	return nil
// }

// // // ValidateBlock checks if the block is valid
// func (bc *BlockchainImpl) ValidateBlock(newBlock *shared.Block, prevBlock *shared.Block) bool {
// 	// Existing checks
// 	if !bytes.Equal(newBlock.PrevHash, prevBlock.Hash) {
// 		fmt.Printf("Invalid previous hash in block %d\n", newBlock.Index)
// 		return false
// 	}

// 	// Add salt validation
// 	if err := bc.validateBlockTransactionSalts(newBlock); err != nil {
// 		fmt.Printf("Invalid transaction salts in block %d: %v\n", newBlock.Index, err)
// 		return false
// 	}

// 	// Rest of existing validation...
// 	if !bc.VerifyPoSRules(*newBlock) {
// 		fmt.Printf("Invalid block %d due to PoS rules: validator was %s\n", newBlock.Index, newBlock.Validator)
// 		return false
// 	}

// 	computedHash := newBlock.ComputeHash()
// 	if !bytes.Equal(newBlock.Hash, computedHash) {
// 		fmt.Printf("Invalid hash in block %d: expected %x, got %x\n", newBlock.Index, computedHash, newBlock.Hash)
// 		return false
// 	}

// 	return true
// }

// func (bc *BlockchainImpl) GetLastBlock() (*shared.Block, int, error) {
// 	// Query the last block data and index
// 	blockData, lastIndex, err := bc.Database.GetLastBlockData()
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			// Handle no rows returned, which means the blockchain is empty
// 			return nil, 0, nil
// 		}
// 		return nil, 0, err
// 	}

// 	// Deserialize the block
// 	var lastBlock shared.Block
// 	buffer := bytes.NewBuffer(blockData)
// 	decoder := gob.NewDecoder(buffer)
// 	err = decoder.Decode(&lastBlock)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	// Return the block along with its index
// 	return &lastBlock, lastIndex, nil
// }

// // // addUTXO adds a new UTXO to the blockchain's UTXO set.
// func (bc *BlockchainImpl) addUTXO(utxo shared.UTXO) error {
// 	utxoKey := fmt.Sprintf("%s:%d", utxo.TransactionID, utxo.Index)
// 	log.Printf("Adding UTXO with key: %s", utxoKey)

// 	if _, exists := bc.UTXOs[utxoKey]; !exists {
// 		bc.UTXOs[utxoKey] = []*thrylos.UTXO{}
// 	}

// 	thrylosUtxo := shared.ConvertSharedUTXOToProto(utxo)
// 	bc.UTXOs[utxoKey] = append(bc.UTXOs[utxoKey], thrylosUtxo)

// 	if err := bc.Database.AddUTXO(utxo); err != nil {
// 		log.Printf("Failed to add UTXO to database: %s", err)
// 		return err
// 	}

// 	log.Printf("UTXO successfully added: %v", utxo)
// 	return nil
// }

// // // removeUTXO removes a UTXO from the blockchain's UTXO set based on transaction ID and index.
// func (bc *BlockchainImpl) removeUTXO(transactionID string, index int32) bool {
// 	utxoKey := fmt.Sprintf("%s:%d", transactionID, index)
// 	if _, exists := bc.UTXOs[utxoKey]; exists {
// 		delete(bc.UTXOs, utxoKey)
// 		return true
// 	}
// 	return false
// }

// // // VerifyTransaction checks the validity of a transaction against the current state of the blockchain,
// // // including signature verification and double spending checks. It's essential for maintaining the
// // // Example snippet for VerifyTransaction method adjustment
// func (bc *BlockchainImpl) VerifyTransaction(tx *thrylos.Transaction) (bool, error) {
// 	// Check if salt is present and valid
// 	if len(tx.Salt) == 0 {
// 		return false, fmt.Errorf("transaction missing salt")
// 	}
// 	if len(tx.Salt) != 32 {
// 		return false, fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
// 	}

// 	// Verify transaction uniqueness using salt
// 	if err := verifyTransactionUniqueness(tx, bc); err != nil {
// 		return false, fmt.Errorf("salt verification failed: %v", err)
// 	}

// 	// Get public key function for verification
// 	getMldsaPublicKeyFunc := func(address string) ([]byte, error) {
// 		pubKey, err := bc.Database.RetrievePublicKeyFromAddress(address)
// 		if err != nil {
// 			return nil, err
// 		}
// 		pubKeyBytes, err := pubKey.MarshalBinary()
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to marshal MLDSA public key: %v", err)
// 		}
// 		return pubKeyBytes, nil
// 	}

// 	// Convert UTXOs to proto format
// 	protoUTXOs := make(map[string][]*thrylos.UTXO)
// 	for key, utxos := range bc.UTXOs {
// 		protoUTXOs[key] = utxos
// 	}

// 	// Verify transaction data
// 	isValid, err := shared.VerifyTransactionData(tx, protoUTXOs, getMldsaPublicKeyFunc)
// 	if err != nil {
// 		return false, fmt.Errorf("transaction data verification failed: %v", err)
// 	}
// 	if !isValid {
// 		return false, fmt.Errorf("invalid transaction data")
// 	}

// 	return true, nil
// }

// // // Helper function to generate a random salt
// func generateSalt() ([]byte, error) {
// 	salt := make([]byte, 32) // Using 32 bytes for salt
// 	_, err := rand.Read(salt)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate salt: %v", err)
// 	}
// 	return salt, nil
// }

// // // AddPendingTransaction adds a new transaction to the pool of pending transactions.
// func (bc *BlockchainImpl) AddPendingTransaction(tx *thrylos.Transaction) error {
// 	// Generate and set salt if not already present
// 	if len(tx.Salt) == 0 {
// 		salt, err := generateSalt()
// 		if err != nil {
// 			return fmt.Errorf("failed to generate salt: %v", err)
// 		}
// 		tx.Salt = salt
// 	}

// 	// Verify salt uniqueness before adding to pending pool
// 	if err := verifyTransactionUniqueness(tx, bc); err != nil {
// 		return fmt.Errorf("transaction salt verification failed: %v", err)
// 	}

// 	// Propagate to all validators before proceeding
// 	if err := bc.TransactionPropagator.PropagateTransaction(tx); err != nil {
// 		return fmt.Errorf("failed to propagate transaction: %v", err)
// 	}
// 	log.Printf("Transaction %s propagated to all validators", tx.Id)

// 	// Start database transaction
// 	txn, err := bc.Database.BeginTransaction()
// 	if err != nil {
// 		return fmt.Errorf("failed to begin transaction: %v", err)
// 	}
// 	defer bc.Database.RollbackTransaction(txn)

// 	// Store transaction with salt
// 	txKey := []byte("transaction-" + tx.Id)
// 	tx.Status = "pending"
// 	txJSON, err := json.Marshal(tx)
// 	if err != nil {
// 		return fmt.Errorf("error marshaling transaction: %v", err)
// 	}

// 	if err := bc.Database.SetTransaction(txn, txKey, txJSON); err != nil {
// 		return fmt.Errorf("error storing transaction: %v", err)
// 	}

// 	if err := bc.Database.CommitTransaction(txn); err != nil {
// 		return fmt.Errorf("error committing transaction: %v", err)
// 	}

// 	bc.Mu.Lock()
// 	bc.PendingTransactions = append(bc.PendingTransactions, tx)
// 	totalPending := len(bc.PendingTransactions)
// 	bc.Mu.Unlock()

// 	log.Printf("Transaction %s with salt added to pending pool. Total pending: %d",
// 		tx.Id, totalPending)

// 	return nil
// }

// // // ProcessPendingTransactions processes all pending transactions, attempting to form a new block.
// func (bc *BlockchainImpl) ProcessPendingTransactions(validator string) (*shared.Block, error) {
// 	// First, verify validator status before acquiring locks
// 	if !bc.IsActiveValidator(validator) {
// 		return nil, fmt.Errorf("invalid validator: %s", validator)
// 	}

// 	// Take a snapshot of pending transactions under lock
// 	bc.Mu.Lock()
// 	if len(bc.PendingTransactions) == 0 {
// 		bc.Mu.Unlock()
// 		return nil, nil // Nothing to process
// 	}
// 	pendingTransactions := make([]*thrylos.Transaction, len(bc.PendingTransactions))
// 	copy(pendingTransactions, bc.PendingTransactions)
// 	bc.Mu.Unlock()

// 	// Start database transaction
// 	txContext, err := bc.Database.BeginTransaction()
// 	if err != nil {
// 		return nil, fmt.Errorf("database transaction error: %v", err)
// 	}
// 	defer bc.Database.RollbackTransaction(txContext)

// 	// Process transactions in batches
// 	successfulTransactions := make([]*thrylos.Transaction, 0, len(pendingTransactions))
// 	for _, tx := range pendingTransactions {
// 		if err := bc.processTransactionInBlock(txContext, tx); err != nil {
// 			log.Printf("Transaction %s failed: %v", tx.ID, err) // Changed Id to ID
// 			continue
// 		}
// 		successfulTransactions = append(successfulTransactions, tx)
// 	}

// 	// Create and sign block
// 	unsignedBlock, err := bc.CreateUnsignedBlock(successfulTransactions, validator)
// 	if err != nil {
// 		return nil, fmt.Errorf("block creation failed: %v", err)
// 	}

// 	signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
// 	if err != nil {
// 		return nil, fmt.Errorf("block signing failed: %v", err)
// 	}

// 	// Commit database changes
// 	if err := bc.Database.CommitTransaction(txContext); err != nil {
// 		return nil, fmt.Errorf("commit failed: %v", err)
// 	}

// 	// Only after successful commit do we update blockchain state
// 	bc.Mu.Lock()
// 	bc.Blocks = append(bc.Blocks, signedBlock)
// 	// Remove processed transactions from pending pool
// 	bc.PendingTransactions = bc.PendingTransactions[len(successfulTransactions):]
// 	bc.Mu.Unlock()

// 	// Async notifications
// 	go func() {
// 		for _, tx := range signedBlock.Transactions {
// 			bc.UpdateTransactionStatus(tx.ID, "included", signedBlock.Hash.String()) // Fixed String method call
// 			if bc.OnTransactionProcessed != nil {
// 				bc.OnTransactionProcessed(tx)
// 			}
// 			bc.notifyBalanceUpdates(tx)
// 		}
// 	}()

// 	return signedBlock, nil
// }

// func (bc *BlockchainImpl) GetActiveValidators() []string {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()
// 	return bc.ActiveValidators
// }

// func (bc *BlockchainImpl) GetStakeholders() map[string]int64 {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()
// 	return bc.Stakeholders
// }

// // // First, ensure when creating transaction inputs we set the original transaction ID
// func (bc *BlockchainImpl) processTransactionInBlock(txContext *shared.TransactionContext, tx *thrylos.Transaction) error {
// 	// Mark input UTXOs as spent
// 	for _, input := range tx.Inputs {
// 		// Validate input fields
// 		if input.TransactionId == "" {
// 			return fmt.Errorf("input UTXO has no transaction_id field set")
// 		}

// 		utxo := shared.UTXO{
// 			TransactionID: input.TransactionId, // This must be the genesis or previous transaction ID
// 			Index:         int(input.Index),
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        int64(input.Amount),
// 			IsSpent:       false,
// 		}

// 		// Debug logging
// 		log.Printf("Processing input UTXO: TransactionID=%s, Index=%d, Owner=%s, Amount=%d",
// 			utxo.TransactionID, utxo.Index, utxo.OwnerAddress, utxo.Amount)

// 		if err := bc.Database.MarkUTXOAsSpent(txContext, utxo); err != nil {
// 			return fmt.Errorf("failed to mark UTXO as spent: %v", err)
// 		}
// 	}

// 	// Create new UTXOs for outputs with the current transaction ID
// 	for i, output := range tx.Outputs {
// 		newUTXO := shared.UTXO{
// 			TransactionID: tx.Id, // Use current transaction's ID for new UTXOs
// 			Index:         i,
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount),
// 			IsSpent:       false,
// 		}

// 		// Debug logging
// 		log.Printf("Creating new UTXO: TransactionID=%s, Index=%d, Owner=%s, Amount=%d",
// 			newUTXO.TransactionID, newUTXO.Index, newUTXO.OwnerAddress, newUTXO.Amount)

// 		if err := bc.Database.AddNewUTXO(txContext, newUTXO); err != nil {
// 			return fmt.Errorf("failed to create new UTXO: %v", err)
// 		}
// 	}

// 	return nil
// }

// func (bc *BlockchainImpl) notifyBalanceUpdates(tx *thrylos.Transaction) {
// 	if bc.OnBalanceUpdate == nil {
// 		return
// 	}

// 	addresses := make(map[string]bool)
// 	addresses[tx.Sender] = true
// 	for _, output := range tx.Outputs {
// 		addresses[output.OwnerAddress] = true
// 	}

// 	for address := range addresses {
// 		balance, err := bc.GetBalance(address)
// 		if err != nil {
// 			log.Printf("Failed to get balance for %s: %v", address, err)
// 			continue
// 		}
// 		bc.OnBalanceUpdate(address, balance)
// 	}
// }

// func (bc *BlockchainImpl) SimulateValidatorSigning(unsignedBlock *shared.Block) (*shared.Block, error) {
// 	log.Printf("Simulating block signing for validator: %s", unsignedBlock.Validator)

// 	privateKey, bech32Address, err := bc.GetValidatorPrivateKey(unsignedBlock.Validator)
// 	if err != nil {
// 		log.Printf("Failed to get validator private key: %v", err)
// 		return nil, fmt.Errorf("failed to get validator private key: %v", err)
// 	}

// 	// Get the private key bytes for hashing
// 	privateKeyBytes, err := privateKey.MarshalBinary()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal private key: %v", err)
// 	}

// 	// Log a hash of the private key for security reasons
// 	privateKeyHash := sha256.Sum256(privateKeyBytes)
// 	log.Printf("Private key hash used for signing: %x", privateKeyHash)

// 	// Update the block's validator address to the Bech32 format
// 	unsignedBlock.Validator = bech32Address
// 	log.Printf("Updated block validator to Bech32 address: %s", bech32Address)

// 	// Generate the block hash
// 	blockHash := unsignedBlock.ComputeHash()
// 	log.Printf("Signing block hash: %x", blockHash)

// 	// Sign the block hash using MLDSA
// 	signature, err := privateKey.Sign(nil, blockHash, nil) // Using crypto/rand by passing nil
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to sign block: %v", err)
// 	}

// 	unsignedBlock.Signature = signature
// 	unsignedBlock.Hash = blockHash

// 	log.Printf("Block signed successfully for validator: %s", unsignedBlock.Validator)
// 	log.Printf("Signature: %x", signature)

// 	// Get the public key for verification
// 	publicKey := privateKey.Public().(*mldsa44.PublicKey)
// 	publicKeyBytes, err := publicKey.MarshalBinary()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal public key: %v", err)
// 	}
// 	log.Printf("Public key derived from private key: %x", publicKeyBytes)

// 	// Verify that this public key is stored correctly
// 	storedPublicKeyBytes, err := bc.Database.RetrieveValidatorPublicKey(bech32Address)
// 	if err != nil {
// 		log.Printf("Failed to retrieve stored public key for validator %s: %v", bech32Address, err)
// 	} else {
// 		log.Printf("Stored public key for validator %s: %x", bech32Address, storedPublicKeyBytes)
// 		if !bytes.Equal(publicKeyBytes, storedPublicKeyBytes) {
// 			log.Printf("WARNING: Derived public key does not match stored public key for validator %s", bech32Address)
// 		}
// 	}

// 	return unsignedBlock, nil
// }

// func (bc *BlockchainImpl) UpdateTransactionStatus(txID string, status string, blockHash []byte) error {
// 	// Begin a new database transaction
// 	txn, err := bc.Database.BeginTransaction()
// 	if err != nil {
// 		return fmt.Errorf("failed to begin database transaction: %v", err)
// 	}
// 	defer bc.Database.RollbackTransaction(txn)

// 	// Retrieve the existing transaction
// 	txKey := []byte("transaction-" + txID)
// 	txItem, err := txn.Txn.Get(txKey)
// 	if err != nil {
// 		// If transaction doesn't exist, create a new one
// 		tx := &thrylos.Transaction{
// 			Id:        txID,
// 			Status:    status,
// 			BlockHash: blockHash,
// 			// Set other required fields that you have available
// 		}
// 		txJSON, err := json.Marshal(tx)
// 		if err != nil {
// 			return fmt.Errorf("error marshaling new transaction: %v", err)
// 		}
// 		if err := bc.Database.SetTransaction(txn, txKey, txJSON); err != nil {
// 			return fmt.Errorf("error storing new transaction: %v", err)
// 		}
// 	} else {
// 		// Update existing transaction
// 		var tx thrylos.Transaction
// 		err = txItem.Value(func(val []byte) error {
// 			return json.Unmarshal(val, &tx)
// 		})
// 		if err != nil {
// 			return fmt.Errorf("error unmarshaling transaction: %v", err)
// 		}

// 		// Update the transaction status
// 		tx.Status = status
// 		tx.BlockHash = blockHash

// 		// Serialize and store the updated transaction
// 		updatedTxJSON, err := json.Marshal(tx)
// 		if err != nil {
// 			return fmt.Errorf("error marshaling updated transaction: %v", err)
// 		}
// 		if err := bc.Database.SetTransaction(txn, txKey, updatedTxJSON); err != nil {
// 			return fmt.Errorf("error updating transaction: %v", err)
// 		}
// 	}

// 	// Commit the transaction
// 	if err := bc.Database.CommitTransaction(txn); err != nil {
// 		return fmt.Errorf("error committing transaction update: %v", err)
// 	}

// 	log.Printf("Transaction %s status updated to %s in block %x", txID, status, blockHash)
// 	return nil
// }

// // // validateTransactionsConcurrently runs transaction validations in parallel and collects errors.
// // Validate transactions with available UTXOs
// func (bc *BlockchainImpl) validateTransactionsConcurrently(transactions []*thrylos.Transaction) []error {
// 	var wg sync.WaitGroup
// 	errChan := make(chan error, len(transactions))

// 	// Convert UTXOs outside the goroutines to avoid concurrent map read/write issues
// 	availableUTXOs := bc.convertUTXOsToRequiredFormat()

// 	for _, tx := range transactions {
// 		wg.Add(1)
// 		go func(tx *thrylos.Transaction) {
// 			defer wg.Done()

// 			// Check if the transaction ID is empty
// 			if tx.Id == "" {
// 				errChan <- fmt.Errorf("transaction ID is empty")
// 				return
// 			}

// 			// Convert each thrylos.Transaction to a shared.Transaction
// 			sharedTx, err := bc.convertToSharedTransaction(tx)
// 			if err != nil {
// 				errChan <- fmt.Errorf("conversion error for transaction ID %s: %v", tx.Id, err)
// 				return
// 			}

// 			// Validate the converted transaction using the shared transaction validation logic
// 			if !shared.ValidateTransaction(sharedTx, availableUTXOs) {
// 				errChan <- fmt.Errorf("validation failed for transaction ID %s", sharedTx.ID)
// 			}
// 		}(tx)
// 	}

// 	wg.Wait()
// 	close(errChan)

// 	var errs []error
// 	for err := range errChan {
// 		if err != nil {
// 			errs = append(errs, err)
// 		}
// 	}
// 	return errs
// }

// // // Helper function to convert thrylos.Transaction to shared.Transaction
// func (bc *BlockchainImpl) convertToSharedTransaction(tx *thrylos.Transaction) (shared.Transaction, error) {
// 	if tx == nil {
// 		return shared.Transaction{}, fmt.Errorf("nil transaction received for conversion")
// 	}

// 	signatureEncoded := base64.StdEncoding.EncodeToString(tx.Signature)

// 	inputs := make([]shared.UTXO, len(tx.Inputs))
// 	for i, input := range tx.Inputs {
// 		inputs[i] = shared.UTXO{
// 			TransactionID: input.TransactionId,
// 			Index:         int(input.Index),
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        int64(input.Amount),
// 		}
// 	}

// 	outputs := make([]shared.UTXO, len(tx.Outputs))
// 	for i, output := range tx.Outputs {
// 		outputs[i] = shared.UTXO{
// 			TransactionID: tx.Id, // Assume output inherits transaction ID
// 			Index:         int(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount),
// 		}
// 	}

// 	return shared.Transaction{
// 		ID:        tx.Id,
// 		Inputs:    inputs,
// 		Outputs:   outputs,
// 		Signature: signatureEncoded,
// 		Timestamp: tx.Timestamp,
// 		Sender:    tx.Sender,
// 	}, nil
// }

// // // Function to convert Blockchain UTXOs to a format usable in shared validation logic
// func (bc *BlockchainImpl) convertUTXOsToRequiredFormat() map[string][]shared.UTXO {
// 	result := make(map[string][]shared.UTXO)
// 	for key, utxos := range bc.UTXOs {
// 		sharedUtxos := make([]shared.UTXO, len(utxos))
// 		for i, utxo := range utxos {
// 			sharedUtxos[i] = shared.UTXO{
// 				TransactionID: utxo.TransactionId,
// 				Index:         int(utxo.Index),
// 				OwnerAddress:  utxo.OwnerAddress,
// 				Amount:        int64(utxo.Amount),
// 			}
// 		}
// 		result[key] = sharedUtxos
// 	}
// 	return result
// }

// // // Get the block and see how many transactions are in each block

// func (bc *BlockchainImpl) GetBlockByID(id string) (shared.Block, error) {
// 	// First, try to parse id as a block index
// 	if index, err := strconv.Atoi(id); err == nil {
// 		// id is a valid integer, so we treat it as a block index
// 		if index >= 0 && index < len(bc.Blocks) {
// 			block := bc.Blocks[index]
// 			log.Printf("Block found by index: Index=%d, Transactions=%v", block.Index, block.Transactions)
// 			return block, nil
// 		}
// 	}

// 	// If id is not a valid index, try to match it as a hash
// 	idBytes, err := hex.DecodeString(id)
// 	if err != nil {
// 		log.Printf("Invalid block ID format: %s", id)
// 		return nil, errors.New("invalid block ID format")
// 	}

// 	// Iterate over blocks and find by hash
// 	for _, block := range bc.Blocks {
// 		if bytes.Equal(block.Hash, idBytes) {
// 			log.Printf("Block found by hash: Index=%d, Transactions=%v", block.Index, block.Transactions)
// 			return block, nil
// 		}
// 	}

// 	log.Println("Block not found with ID:", id)
// 	return nil, errors.New("block not found")
// }

// func (bc *BlockchainImpl) GetTransactionByID(id string) (*thrylos.Transaction, error) {
// 	// iterate over blocks and transactions to find by ID
// 	for _, block := range bc.Blocks {
// 		for _, tx := range block.Transactions {
// 			if tx.Id == id {
// 				return tx, nil
// 			}
// 		}
// 	}
// 	return nil, errors.New("transaction not found")
// }

// // // This function should return the number of blocks in the blockchain.

// func (bc *BlockchainImpl) GetBlockCount() int {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()
// 	return len(bc.Blocks)
// }

// // // This function should return the number of transactions for a given address, which is often referred to as the "nonce."

// func (bc *BlockchainImpl) GetTransactionCount(address string) int {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	count := 0
// 	for _, block := range bc.Blocks {
// 		for _, transaction := range block.Transactions {
// 			if transaction.Sender == address {
// 				count++
// 			}
// 		}
// 	}
// 	return count
// }

// func (bc *Blockchain) GetBlock(blockNumber int) (*shared.Block, error) {
// 	blockData, err := bc.Database.RetrieveBlock(blockNumber)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
// 	}

// 	var block shared.Block
// 	if err := json.Unmarshal(blockData, &block); err != nil { // Deserialize here
// 		return nil, fmt.Errorf("failed to deserialize block: %v", err)
// 	}
// 	return &block, nil
// }

// func (bc *BlockchainImpl) RegisterValidator(address string, pubKey string, bypassStakeCheck bool) error {
// 	log.Printf("Entering RegisterValidator function for address: %s", address)

// 	lockChan := make(chan struct{})
// 	go func() {
// 		bc.Mu.Lock()
// 		close(lockChan)
// 	}()

// 	select {
// 	case <-lockChan:
// 		log.Printf("Lock acquired for address: %s", address)
// 		defer func() {
// 			bc.Mu.Unlock()
// 			log.Printf("Lock released for address: %s", address)
// 		}()
// 	case <-time.After(10 * time.Second):
// 		return fmt.Errorf("timeout while acquiring lock for address: %s", address)
// 	}

// 	// Sanitize and format the address
// 	formattedAddress, err := shared.SanitizeAndFormatAddress(address)
// 	if err != nil {
// 		log.Printf("Invalid address format for %s: %v", address, err)
// 		return fmt.Errorf("invalid address format: %v", err)
// 	}
// 	log.Printf("Formatted address: %s", formattedAddress)

// 	// Decode base64 public key
// 	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
// 	if err != nil {
// 		return fmt.Errorf("error decoding public key: %v", err)
// 	}

// 	// Create and parse MLDSA public key
// 	mldsaPubKey := new(mldsa44.PublicKey)
// 	err = mldsaPubKey.UnmarshalBinary(pubKeyBytes)
// 	if err != nil {
// 		return fmt.Errorf("invalid MLDSA public key format: %v", err)
// 	}

// 	// Store the public key in memory
// 	bc.PublicKeyMap[formattedAddress] = mldsaPubKey
// 	log.Printf("Stored public key in memory for address: %s", formattedAddress)

// 	// Validate stake if not bypassing check
// 	if !bypassStakeCheck {
// 		stake, exists := bc.Stakeholders[formattedAddress]
// 		if !exists || stake < bc.MinStakeForValidator.Int64() {
// 			log.Printf("Insufficient stake for %s: exists=%v, stake=%d, minStake=%d",
// 				formattedAddress, exists, stake, bc.MinStakeForValidator.Int64())
// 			return fmt.Errorf("insufficient stake or not found")
// 		}
// 	}

// 	log.Printf("Stake check bypassed or passed for %s", formattedAddress)

// 	// Store in the database with a timeout
// 	log.Printf("Attempting to store public key in database for address: %s", formattedAddress)
// 	dbChan := make(chan error, 1)
// 	go func() {
// 		dbChan <- bc.Database.StoreValidatorMLDSAPublicKey(formattedAddress, mldsaPubKey)
// 	}()

// 	select {
// 	case err := <-dbChan:
// 		if err != nil {
// 			log.Printf("Failed to store public key in database for %s: %v", formattedAddress, err)
// 			return fmt.Errorf("failed to store public key in database: %v", err)
// 		}
// 	case <-time.After(5 * time.Second):
// 		log.Printf("Database operation timed out for %s", formattedAddress)
// 		return fmt.Errorf("database operation timed out")
// 	}

// 	log.Printf("Successfully stored public key in database for address: %s", formattedAddress)

// 	// Assign the minimum stake to the new validator
// 	minStake := bc.MinStakeForValidator.Int64()
// 	bc.Stakeholders[formattedAddress] = minStake
// 	log.Printf("Assigned minimum stake %d to validator %s", minStake, formattedAddress)

// 	log.Printf("Validator registered successfully: address=%s", formattedAddress)
// 	return nil
// }

// func (bc *BlockchainImpl) StoreValidatorPrivateKey(address string, privKeyBytes []byte) error {
// 	log.Printf("Storing private key for validator: %s", address)

// 	// Create and parse MLDSA private key
// 	mldsaPrivKey := new(mldsa44.PrivateKey)
// 	err := mldsaPrivKey.UnmarshalBinary(privKeyBytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse MLDSA private key for validator %s: %v", address, err)
// 	}

// 	if err := bc.ValidatorKeys.StoreKey(address, mldsaPrivKey); err != nil {
// 		log.Printf("Failed to store private key for validator %s: %v", address, err)
// 		return fmt.Errorf("failed to store private key for validator %s: %v", address, err)
// 	}

// 	log.Printf("Private key for validator %s stored securely", address)
// 	return nil
// }

// func (bc *BlockchainImpl) GetValidatorPrivateKey(validatorAddress string) (*mldsa44.PrivateKey, string, error) {
// 	log.Printf("Attempting to retrieve private key for validator: %s", validatorAddress)

// 	// Check if the validator is active
// 	if !bc.IsActiveValidator(validatorAddress) {
// 		log.Printf("Validator %s is not in the active validator list", validatorAddress)
// 		return nil, "", fmt.Errorf("validator is not active: %s", validatorAddress)
// 	}

// 	// Retrieve the private key from the ValidatorKeys store
// 	privateKey, exists := bc.ValidatorKeys.GetKey(validatorAddress)
// 	if !exists {
// 		log.Printf("Failed to retrieve private key for validator %s", validatorAddress)
// 		return nil, "", fmt.Errorf("failed to retrieve private key for validator %s", validatorAddress)
// 	}

// 	// Convert the validator address to Bech32 format
// 	bech32Address, err := ConvertToBech32Address(validatorAddress)
// 	if err != nil {
// 		log.Printf("Failed to convert validator address %s to Bech32 format: %v", validatorAddress, err)
// 		return privateKey, "", err
// 	}

// 	return privateKey, bech32Address, nil
// }

// func generateBech32Address(publicKey *mldsa44.PublicKey) (string, error) {
// 	// First marshal the public key to bytes
// 	pubKeyBytes, err := publicKey.MarshalBinary()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to marshal public key: %v", err)
// 	}

// 	// Generate SHA256 hash of the marshaled public key
// 	hash := sha256.Sum256(pubKeyBytes)

// 	// Take first 20 bytes of the hash for the address
// 	converted, err := bech32.ConvertBits(hash[:20], 8, 5, true)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to convert bits for Bech32 address: %v", err)
// 	}

// 	// Encode with tl1 prefix
// 	bech32Address, err := bech32.Encode("tl1", converted)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to encode Bech32 address: %v", err)
// 	}

// 	return bech32Address, nil
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

// func (bc *BlockchainImpl) TransferFunds(from, to string, amount int64) error {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	if from == "" {
// 		from = bc.GenesisAccount // Default to the genesis account if 'from' is not specified
// 	}

// 	// Check if the sender has enough funds
// 	if bc.Stakeholders[from] < amount {
// 		return fmt.Errorf("insufficient funds")
// 	}

// 	// Perform the transfer
// 	bc.Stakeholders[from] -= amount
// 	bc.Stakeholders[to] += amount

// 	return nil
// }

// func (bc *BlockchainImpl) UpdateActiveValidators(count int) {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	// Sort stakeholders by stake amount
// 	type validatorStake struct {
// 		address string
// 		amount  int64
// 	}
// 	validators := make([]validatorStake, 0)

// 	minValidatorStake := int64(40 * 1e7) // 40 THRYLOS minimum for validators

// 	for addr, stake := range bc.Stakeholders {
// 		if stake >= minValidatorStake { // Using fixed minimum validator stake
// 			validators = append(validators, validatorStake{addr, stake})
// 		}
// 	}

// 	// Sort by stake amount (descending)
// 	sort.Slice(validators, func(i, j int) bool {
// 		return validators[i].amount > validators[j].amount
// 	})

// 	// Update active validators list
// 	bc.ActiveValidators = make([]string, 0)
// 	for i := 0; i < min(count, len(validators)); i++ {
// 		bc.ActiveValidators = append(bc.ActiveValidators, validators[i].address)
// 	}
// }

// func SharedToThrylos(tx *shared.Transaction) *thrylos.Transaction {
// 	if tx == nil {
// 		return nil
// 	}

// 	signatureBytes, _ := base64.StdEncoding.DecodeString(tx.Signature)

// 	// Generate salt for new transaction if not present
// 	salt := tx.Salt
// 	if len(salt) == 0 {
// 		var err error
// 		salt, err = generateSalt()
// 		if err != nil {
// 			log.Printf("Failed to generate salt: %v", err)
// 			return nil
// 		}
// 	}

// 	return &thrylos.Transaction{
// 		Id:            tx.ID,
// 		Timestamp:     tx.Timestamp,
// 		Inputs:        ConvertSharedInputs(tx.Inputs),
// 		Outputs:       ConvertSharedOutputs(tx.Outputs),
// 		Signature:     signatureBytes,
// 		Salt:          salt,
// 		PreviousTxIds: tx.PreviousTxIds,
// 		Sender:        tx.Sender,
// 		Status:        tx.Status,
// 		Gasfee:        int32(tx.GasFee),
// 	}
// }

// func ConvertSharedOutputs(outputs []shared.UTXO) []*thrylos.UTXO {
// 	result := make([]*thrylos.UTXO, len(outputs))
// 	for i, output := range outputs {
// 		result[i] = &thrylos.UTXO{
// 			TransactionId: output.TransactionID,
// 			Index:         int32(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        output.Amount,
// 			IsSpent:       output.IsSpent,
// 		}
// 	}
// 	return result
// }

// func ConvertSharedInputs(inputs []shared.UTXO) []*thrylos.UTXO {
// 	return ConvertSharedOutputs(inputs) // Same conversion process
// }

// // // Now we can update ProcessPoolTransaction to use these conversion functions
// func (bc *BlockchainImpl) ProcessPoolTransaction(tx *shared.Transaction) error {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	// Convert shared.Transaction to thrylos.Transaction
// 	thrylosTx := SharedToThrylos(tx)

// 	// Verify pool-related transaction
// 	if tx.Sender == "staking_pool" || tx.Outputs[0].OwnerAddress == "staking_pool" {
// 		// Use original shared.Transaction for validation
// 		if err := bc.validatePoolTransaction(tx); err != nil {
// 			return err
// 		}
// 	}

// 	return bc.AddPendingTransaction(thrylosTx)
// }

// func (bc *BlockchainImpl) validatePoolTransaction(tx *shared.Transaction) error {
// 	// Implement pool-specific transaction validation
// 	if tx.Sender == "staking-pool" {
// 		// Validate undelegation
// 		delegator := tx.Outputs[0].OwnerAddress
// 		amount := tx.Outputs[0].Amount

// 		// Check if undelegation amount is valid
// 		totalDelegated := bc.StakingService.stakes[delegator].Amount
// 		if totalDelegated < amount {
// 			return errors.New("invalid undelegation amount")
// 		}
// 	}

// 	return nil
// }

// // // Helper function to get delegation pool stats
// func (bc *BlockchainImpl) GetPoolStats() map[string]interface{} {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	return bc.StakingService.GetPoolStats()
// }

// func GenerateValidatorAddress() (string, error) {
// 	// Generate a random 32-byte seed
// 	seed := new([mldsa44.SeedSize]byte)
// 	_, err := rand.Read(seed[:])
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate seed: %v", err)
// 	}

// 	// Generate ML-DSA-44 private and public keys from the seed
// 	publicKey, privateKey := mldsa44.NewKeyFromSeed(seed)
// 	_ = privateKey // Private key can be stored securely if needed

// 	// Serialize the public key
// 	publicKeyBytes := publicKey.Bytes()

// 	// Hash the public key
// 	hash := sha256.Sum256(publicKeyBytes)

// 	// Use the first 20 bytes of the hash as the address bytes
// 	addressBytes := hash[:20]

// 	// Convert to 5-bit groups for bech32 encoding
// 	converted, err := bech32.ConvertBits(addressBytes, 8, 5, true)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to convert bits: %v", err)
// 	}

// 	// Encode using bech32
// 	address, err := bech32.Encode("tl1", converted)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to encode address: %v", err)
// 	}

// 	return address, nil
// }

// func (bc *BlockchainImpl) GenerateAndStoreValidatorKey() (string, error) {
// 	address, err := GenerateValidatorAddress()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate validator address: %v", err)
// 	}

// 	// Generate MLDSA key pair directly
// 	pubKey, privKey, err := mldsa44.GenerateKey(rand.Reader)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to generate MLDSA key pair: %v", err)
// 	}

// 	// Marshal the public key
// 	pubKeyBytes, err := pubKey.MarshalBinary()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to marshal public key: %v", err)
// 	}
// 	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

// 	// Register the validator
// 	err = bc.RegisterValidator(address, pubKeyBase64, true)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to register validator: %v", err)
// 	}

// 	// Store the private key
// 	err = bc.ValidatorKeys.StoreKey(address, privKey)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to store validator private key: %v", err)
// 	}

// 	return address, nil
// }

// // // For generating multiple Validator Keys if necessary
// func (bc *BlockchainImpl) GenerateAndStoreValidatorKeys(count int) ([]string, error) {
// 	log.Printf("Starting to generate and store %d validator keys", count)
// 	validatorAddresses := make([]string, 0, count)

// 	for i := 0; i < count; i++ {
// 		log.Printf("Generating validator key %d of %d", i+1, count)

// 		// Generate validator address
// 		address, err := GenerateValidatorAddress()
// 		if err != nil {
// 			log.Printf("Failed to generate validator address: %v", err)
// 			return validatorAddresses, fmt.Errorf("failed to generate validator address: %v", err)
// 		}

// 		// Generate MLDSA key pair directly
// 		pubKey, privKey, err := mldsa44.GenerateKey(rand.Reader)
// 		if err != nil {
// 			log.Printf("Failed to generate MLDSA key pair: %v", err)
// 			return validatorAddresses, fmt.Errorf("failed to generate MLDSA key pair: %v", err)
// 		}

// 		// Store the private key
// 		err = bc.ValidatorKeys.StoreKey(address, privKey)
// 		if err != nil {
// 			log.Printf("Failed to store validator private key: %v", err)
// 			return validatorAddresses, fmt.Errorf("failed to store validator private key: %v", err)
// 		}

// 		// Store the public key in the database
// 		err = bc.Database.StoreValidatorMLDSAPublicKey(address, pubKey)
// 		if err != nil {
// 			log.Printf("Failed to store validator public key: %v", err)
// 			return validatorAddresses, fmt.Errorf("failed to store validator public key: %v", err)
// 		}

// 		// Verify the key was stored correctly
// 		publicKeyBytes, err := bc.Database.RetrieveValidatorPublicKey(address)
// 		if err != nil {
// 			log.Printf("Error retrieving validator public key immediately after storage: %v", err)
// 			return validatorAddresses, fmt.Errorf("failed to verify stored validator key: %v", err)
// 		}

// 		// Parse the public key bytes into MLDSA public key for verification
// 		verifyPubKey := new(mldsa44.PublicKey)
// 		err = verifyPubKey.UnmarshalBinary(publicKeyBytes)
// 		if err != nil {
// 			log.Printf("Failed to parse MLDSA public key for address %s: %v", address, err)
// 			return validatorAddresses, fmt.Errorf("invalid public key format for address %s: %v", address, err)
// 		}

// 		// Verify the keys match
// 		if !verifyPubKey.Equal(pubKey) {
// 			log.Printf("Stored public key does not match generated key for address %s", address)
// 			return validatorAddresses, fmt.Errorf("key verification failed for address %s", address)
// 		}

// 		log.Printf("Successfully verified stored validator public key for address: %s (Key size: %d bytes)",
// 			address, len(publicKeyBytes))

// 		// Add the verified key to the PublicKeyMap
// 		bc.PublicKeyMap[address] = pubKey

// 		log.Printf("Successfully generated and stored validator key %d: %s", i+1, address)
// 		validatorAddresses = append(validatorAddresses, address)
// 	}

// 	log.Printf("Finished generating and storing %d validator keys", len(validatorAddresses))
// 	return validatorAddresses, nil
// }

// func min(a, b int) int {
// 	if a < b {
// 		return a
// 	}
// 	return b
// }

// func (bc *BlockchainImpl) validatorExists(address string) bool {
// 	_, err := bc.RetrievePublicKey(address)
// 	return err == nil
// }

// func (bc *BlockchainImpl) IsActiveValidator(address string) bool {
// 	bc.Mu.RLock()
// 	defer bc.Mu.RUnlock()

// 	for _, validator := range bc.ActiveValidators {
// 		if validator == address {
// 			return true
// 		}
// 	}
// 	return false
// }

// // // AddBlock adds a new block to the blockchain, with an optional timestamp.
// // // If the timestamp is 0, the current system time is used as the block's timestamp.
// func (bc *BlockchainImpl) AddBlock(transactions []*thrylos.Transaction, validator string, prevHash []byte, optionalTimestamp ...int64) (bool, error) {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	// Handle potential forks.
// 	if len(bc.Blocks) > 0 && !bytes.Equal(prevHash, bc.Blocks[len(bc.Blocks)-1].Hash) {
// 		var selectedFork *Fork
// 		for _, fork := range bc.Forks {
// 			if bytes.Equal(fork.Blocks[len(fork.Blocks)-1].Hash, prevHash) {
// 				selectedFork = fork
// 				break
// 			}
// 		}

// 		// Create unsigned block for the fork
// 		unsignedBlock, err := bc.CreateUnsignedBlock(transactions, validator)
// 		if err != nil {
// 			return false, fmt.Errorf("failed to create unsigned block: %v", err)
// 		}

// 		// Simulate validator signing
// 		signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
// 		if err != nil {
// 			return false, fmt.Errorf("failed to simulate block signing: %v", err)
// 		}

// 		// Verify the signed block
// 		if err := bc.VerifySignedBlock(signedBlock); err != nil {
// 			return false, fmt.Errorf("invalid signed block: %v", err)
// 		}

// 		blockData, err := json.Marshal(signedBlock)
// 		if err != nil {
// 			return false, fmt.Errorf("failed to serialize new block: %v", err)
// 		}

// 		blockNumber := len(bc.Blocks)
// 		if selectedFork != nil {
// 			selectedFork.Blocks = append(selectedFork.Blocks, signedBlock)
// 			blockNumber = len(selectedFork.Blocks) - 1
// 		} else {
// 			bc.Blocks = append(bc.Blocks, signedBlock)
// 			blockNumber = len(bc.Blocks) - 1
// 		}

// 		if err := bc.Database.StoreBlock(blockData, blockNumber); err != nil {
// 			return false, fmt.Errorf("failed to store block in database: %v", err)
// 		}

// 		return true, nil
// 	}

// 	// Verify transactions.
// 	for _, tx := range transactions {
// 		isValid, err := bc.VerifyTransaction(tx)
// 		if err != nil || !isValid {
// 			return false, fmt.Errorf("transaction verification failed: %s, error: %v", tx.GetId(), err)
// 		}
// 	}

// 	// Create unsigned block
// 	unsignedBlock, err := bc.CreateUnsignedBlock(transactions, validator)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to create unsigned block: %v", err)
// 	}

// 	// Simulate validator signing
// 	signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to simulate block signing: %v", err)
// 	}

// 	// Verify the signed block
// 	if err := bc.VerifySignedBlock(signedBlock); err != nil {
// 		return false, fmt.Errorf("invalid signed block: %v", err)
// 	}

// 	// Update UTXO set
// 	for _, tx := range signedBlock.Transactions {
// 		// Remove spent UTXOs
// 		for _, input := range tx.GetInputs() {
// 			utxoKey := fmt.Sprintf("%s:%d", input.GetTransactionId(), input.GetIndex())
// 			delete(bc.UTXOs, utxoKey)
// 		}
// 		// Add new UTXOs
// 		for index, output := range tx.GetOutputs() {
// 			utxoKey := fmt.Sprintf("%s:%d", tx.GetId(), index)
// 			bc.UTXOs[utxoKey] = []*thrylos.UTXO{output}
// 		}
// 	}

// 	// Serialize and store the block
// 	blockData, err := json.Marshal(signedBlock)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to serialize new block: %v", err)
// 	}

// 	blockNumber := len(bc.Blocks)
// 	if err := bc.Database.StoreBlock(blockData, blockNumber); err != nil {
// 		return false, fmt.Errorf("failed to store block in database: %v", err)
// 	}

// 	// Update the blockchain with the new block
// 	bc.Blocks = append(bc.Blocks, signedBlock)
// 	bc.lastTimestamp = signedBlock.Timestamp

// 	if bc.OnNewBlock != nil {
// 		bc.OnNewBlock(signedBlock)
// 	}

// 	// Update balances for affected addresses
// 	bc.updateBalancesForBlock(signedBlock)

// 	return true, nil
// }

// func (bc *BlockchainImpl) updateBalancesForBlock(block *shared.Block) {
// 	for _, tx := range block.Transactions {
// 		// Update sender's balance
// 		senderBalance, _ := bc.GetBalance(tx.Sender)
// 		bc.Stakeholders[tx.Sender] = senderBalance // directly use int64 value

// 		// Update recipients' balances
// 		for _, output := range tx.Outputs {
// 			recipientBalance, _ := bc.GetBalance(output.OwnerAddress)
// 			bc.Stakeholders[output.OwnerAddress] = recipientBalance // directly use int64 value
// 		}
// 	}
// }

// // RewardValidator rewards the validator with new tokens
// func (bc *BlockchainImpl) RewardValidator(validator string, reward int64) {
// 	bc.Mu.Lock()
// 	defer bc.Mu.Unlock()

// 	// Deduct reward from Genesis account
// 	bc.Stakeholders[bc.GenesisAccount] -= reward
// 	// Add reward to validator
// 	bc.Stakeholders[validator] += reward
// }

// // // VerifyPoSRules verifies the PoS rules for the given block
// func (bc *BlockchainImpl) VerifyPoSRules(block shared.Block) bool {
// 	// Check if the validator had a stake at the time of block creation
// 	_, exists := bc.Stakeholders[block.Validator]
// 	return exists
// }

// // // CheckChainIntegrity verifies the entire blockchain for hash integrity and chronological order,
// // // ensuring that no blocks have been altered or inserted maliciously. It's a safeguard against tampering
// // // and a key component in the blockchain's security mechanisms.
// func (bc *BlockchainImpl) CheckChainIntegrity() bool {
// 	for i := 1; i < len(bc.Blocks); i++ {
// 		prevBlock := bc.Blocks[i-1]
// 		currentBlock := bc.Blocks[i]

// 		if !bytes.Equal(currentBlock.PrevHash, prevBlock.Hash) {
// 			fmt.Printf("Invalid previous hash in block %d. Expected %x, got %x\n",
// 				currentBlock.Index, prevBlock.Hash, currentBlock.PrevHash)
// 			return false
// 		}

// 		computedHash := currentBlock.ComputeHash()
// 		if !bytes.Equal(currentBlock.Hash, computedHash) {
// 			fmt.Printf("Invalid hash in block %d. Expected %x, got %x\n",
// 				currentBlock.Index, computedHash, currentBlock.Hash)
// 			return false
// 		}
// 	}
// 	return true
// }
