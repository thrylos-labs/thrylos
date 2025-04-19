package chaintests

// func TestNewBlockchain(t *testing.T) {
// 	// Try to load env but don't fail if it doesn't exist
// 	err := godotenv.Load(".env.dev")
// 	if err != nil {
// 		log.Printf("Note: .env.dev file not found, using default test values")
// 	}

// 	// Create a unique temporary directory for the test
// 	tempDir, err := os.MkdirTemp("", fmt.Sprintf("blockchain_test_%d", time.Now().UnixNano()))
// 	require.NoError(t, err, "Failed to create temporary directory")

// 	// Clean up the temporary directory after the test

// 	// Generate test keys
// 	priv, err := crypto.NewPrivateKey()
// 	require.NoError(t, err, "Failed to generate private key for genesis account")

// 	aesKey, err := encryption.GenerateAESKey()
// 	require.NoError(t, err, "Failed to generate AES key")

// 	// Initialize blockchain config
// 	config := &types.BlockchainConfig{
// 		DataDir:           tempDir,
// 		AESKey:            aesKey,
// 		GenesisAccount:    priv,
// 		TestMode:          true,
// 		DisableBackground: true,
// 	}

// 	// Create blockchain instance
// 	blockchain, blockchainStore, err := chain.NewBlockchain(config)
// 	require.NoError(t, err, "Failed to create blockchain")
// 	require.NotNil(t, blockchain, "Blockchain should not be nil")
// 	require.NotNil(t, blockchainStore, "Blockchain store should not be nil")

// 	// Verify blockchain structure
// 	require.NotNil(t, blockchain.Blockchain, "Blockchain.Blockchain should not be nil")
// 	require.NotNil(t, blockchain.Blockchain.Genesis, "Genesis block should not be nil")
// 	require.NotEmpty(t, blockchain.Blockchain.Blocks, "Blockchain should have at least one block")
// 	require.Equal(t, blockchain.Blockchain.Genesis, blockchain.Blockchain.Blocks[0], "First block should be genesis block")

// 	// Add more robust cleanup
// 	defer func() {
// 		// First close the blockchain store if it exists
// 		if blockchainStore != nil {
// 			if closer, ok := blockchainStore.(interface{ Close() error }); ok {
// 				if err := closer.Close(); err != nil {
// 					t.Logf("Warning: Failed to close blockchain store: %v", err)
// 				}
// 			}
// 		}

// 		// Clean up the temporary directory
// 		if err := os.RemoveAll(tempDir); err != nil {
// 			t.Logf("Warning: Failed to remove temp directory: %v", err)
// 		}
// 	}()

// 	// Verify genesis block structure
// 	genesis := blockchain.Blockchain.Genesis
// 	require.NotEmpty(t, genesis.Transactions, "Genesis block should have at least one transaction")

// 	// Verify UTXOs are initialized
// 	require.NotNil(t, blockchain.Blockchain.UTXOs, "Blockchain UTXOs map should not be nil")

// 	// Verify genesis transaction
// 	genesisTx := genesis.Transactions[0]
// 	require.NotNil(t, genesisTx, "Genesis transaction should not be nil")
// 	require.NotEmpty(t, genesisTx.ID, "Genesis transaction should have an ID")

// 	// Verify the genesis block can be retrieved from the store using block number 0
// 	savedBlock, err := blockchainStore.GetBlock(0)
// 	require.NoError(t, err, "Should be able to retrieve genesis block from store")
// 	require.NotNil(t, savedBlock, "Retrieved genesis block should not be nil")

// 	// Additional verification of the saved block
// 	require.Equal(t, len(genesis.Transactions), len(savedBlock.Transactions), "Saved block should have same number of transactions as genesis block")
// 	require.Equal(t, genesis.Hash, savedBlock.Hash, "Saved block hash should match genesis block hash")
// }

// func TestSignature(t *testing.T) {
// 	// Generate a new key pair
// 	privateKey, err := crypto.NewPrivateKey()
// 	if err != nil {
// 		t.Fatalf(" key generation failed: %v", err)
// 	}

// 	// Create a mock transaction (simplified representation)
// 	tx := "mock transaction"
// 	txBytes := []byte(tx)

// 	// Sign the transaction
// 	signature := privateKey.Sign(txBytes)
// 	if err != nil {
// 		t.Fatalf(" signing failed: %v", err)
// 	}

// 	// Verify the signature using the scheme's Verify function
// 	pubKey := privateKey.PublicKey()
// 	err = signature.Verify(&pubKey, txBytes)
// 	if err != nil {
// 		t.Fatal(" signature verification failed")
// 	}

// 	t.Log("MLDSA44 signature verification succeeded")
// }
