package chaintests

// func TestGenesisBlockCreation(t *testing.T) {
// 	// Set a properly formatted genesis account address
// 	genesisAccount := "tl1dummy_genesis_account_value" // Changed to start with tl1
// 	os.Setenv("GENESIS_ACCOUNT", genesisAccount)
// 	defer os.Unsetenv("GENESIS_ACCOUNT")

// 	// Create a temporary directory for blockchain data with a unique suffix
// 	tempDir, err := ioutil.TempDir("", fmt.Sprintf("blockchain_test_%d", time.Now().UnixNano()))
// 	if err != nil {
// 		t.Fatalf("Failed to create temporary directory: %v", err)
// 	}

// 	// Cleanup function
// 	cleanup := func() {
// 		time.Sleep(100 * time.Millisecond)
// 		lockFile := filepath.Join(tempDir, "LOCK")
// 		if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) {
// 			t.Logf("Warning: Failed to remove lock file: %v", err)
// 		}
// 		manifestFiles, err := filepath.Glob(filepath.Join(tempDir, "MANIFEST*"))
// 		if err == nil {
// 			for _, f := range manifestFiles {
// 				if err := os.Remove(f); err != nil {
// 					t.Logf("Warning: Failed to remove manifest file %s: %v", f, err)
// 				}
// 			}
// 		}
// 		time.Sleep(100 * time.Millisecond)
// 		if err := os.RemoveAll(tempDir); err != nil {
// 			t.Logf("Warning: Failed to remove temp directory: %v", err)
// 		}
// 	}
// 	defer cleanup()

// 	// Generate a dummy AES key for testing
// 	aesKey, err := encryption.GenerateAESKey()
// 	if err != nil {
// 		t.Fatalf("Failed to generate AES key: %v", err)
// 	}

// 	// Create the genesis account private key
// 	genesisAccount = os.Getenv("GENESIS_ACCOUNT")
// 	if genesisAccount == "" {
// 		t.Fatal("Genesis account is not set in environment variables. This should not happen.")
// 	}
// 	priv, err := crypto.NewPrivateKeyFromBytes([]byte(genesisAccount))
// 	if err != nil {
// 		t.Fatal("Error converting the genesis account into a private key.")
// 	}

// 	// Initialize blockchain with correct config type
// 	config := &types.BlockchainConfig{
// 		DataDir:           tempDir,
// 		AESKey:            aesKey,
// 		GenesisAccount:    priv,
// 		TestMode:          true,
// 		DisableBackground: true,
// 	}

// 	blockchain, store, err := chain.NewBlockchain(config)
// 	if err != nil {
// 		cleanup()
// 		t.Fatalf("Failed to initialize blockchain: %v", err)
// 	}

// 	// Ensure store is closed before cleanup
// 	if closer, ok := store.(interface{ Close() }); ok {
// 		defer func() {
// 			closer.Close()
// 			time.Sleep(100 * time.Millisecond)
// 		}()
// 	}

// 	// Verify the genesis block
// 	if blockchain == nil || blockchain.Blockchain == nil {
// 		t.Fatal("Blockchain or Blockchain.Blockchain is nil")
// 	}

// 	if len(blockchain.Blockchain.Blocks) == 0 {
// 		t.Error("Blockchain has no blocks")
// 	}

// 	if blockchain.Blockchain.Genesis == nil {
// 		t.Error("Genesis block is nil")
// 	}

// 	if len(blockchain.Blockchain.Blocks) > 0 && blockchain.Blockchain.Blocks[0] != blockchain.Blockchain.Genesis {
// 		t.Error("First block is not the genesis block")
// 	}

// 	// Verify genesis transaction
// 	genesisBlock := blockchain.Blockchain.Genesis
// 	if len(genesisBlock.Transactions) == 0 {
// 		t.Error("Genesis block has no transactions")
// 	}

// 	// Verify stakeholders map initialization
// 	if len(blockchain.Blockchain.Stakeholders) == 0 {
// 		t.Error("Stakeholders map not initialized")
// 	}

// 	// Verify UTXO map initialization
// 	if len(blockchain.Blockchain.UTXOs) == 0 {
// 		t.Error("UTXO map not initialized")
// 	}
// }

// func TestBlockCreation(t *testing.T) {
// 	privateKey, err := crypto.NewPrivateKey()
// 	if err != nil {
// 		t.Fatalf("Failed to generate private key: %v", err)
// 	}
// 	//stakeAmount := amount.Amount(100)
// 	index := int64(1)
// 	prevHash := hash.NewHash([]byte("previous-hash"))
// 	pubKey := privateKey.PublicKey()
// 	//val := validator.NewValidator(privateKey, index, stakeAmount)
// 	//tx:= shared.NewTransaction()
// 	b, err := chain.NewBlock(index, prevHash, nil, pubKey)
// 	if err != nil {
// 		t.Logf("error creating a block: %v", err)
// 	}
// 	err = chain.Verify(b)
// 	if err != nil {
// 		t.Logf("error verifing the block... this should fail because the block has no transactions: %v", err)
// 	}
// }
