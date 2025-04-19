package chaintests

// func TestAddTransaction(t *testing.T) {
// 	// Create a temporary directory for the test database
// 	tempDir, err := os.MkdirTemp("", "txpool_test")
// 	assert.NoError(t, err)

// 	// Clean up the temporary directory after the test completes
// 	defer os.RemoveAll(tempDir)

// 	// Create the database directly for the test
// 	db, err := store.NewDatabase(tempDir)
// 	assert.NoError(t, err)
// 	defer db.Close()

// 	// Create a proper private key for testing
// 	privKey, err := crypto.NewPrivateKey()
// 	assert.NoError(t, err)

// 	// Create a minimal blockchain config for testing
// 	config := &types.BlockchainConfig{
// 		DataDir:        tempDir,
// 		GenesisAccount: privKey,
// 		TestMode:       true,
// 	}

// 	// Create the blockchain using the NewBlockchain constructor
// 	blockchain, _, err := chain.NewBlockchain(config)
// 	assert.NoError(t, err)

// 	// Now create the transaction pool with the required arguments
// 	pool := chain.NewTxPool(db, blockchain)
// 	tx := &types.Transaction{ID: "tx1"}

// 	// Add a transaction
// 	err = pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	// Try adding the same transaction again - should error
// 	err = pool.AddTransaction(tx)
// 	assert.Error(t, err)
// }

// func TestRemoveTransaction(t *testing.T) {
// 	// Create a temporary directory for the test database
// 	tempDir, err := os.MkdirTemp("", "txpool_test")
// 	assert.NoError(t, err)

// 	// Clean up the temporary directory after the test completes
// 	defer os.RemoveAll(tempDir)

// 	// Create the database directly for the test
// 	db, err := store.NewDatabase(tempDir)
// 	assert.NoError(t, err)
// 	defer db.Close()

// 	// Create a proper private key for testing
// 	privKey, err := crypto.NewPrivateKey()
// 	assert.NoError(t, err)

// 	// Create a minimal blockchain config for testing
// 	config := &types.BlockchainConfig{
// 		DataDir:        tempDir,
// 		GenesisAccount: privKey,
// 		TestMode:       true,
// 	}

// 	// Create the blockchain using the NewBlockchain constructor
// 	blockchain, _, err := chain.NewBlockchain(config)
// 	assert.NoError(t, err)

// 	// Now create the transaction pool with the required arguments
// 	pool := chain.NewTxPool(db, blockchain)
// 	tx := &types.Transaction{ID: "tx1"}

// 	err = pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	err = pool.RemoveTransaction(tx)
// 	assert.NoError(t, err)

// 	// Try removing the same transaction again
// 	err = pool.RemoveTransaction(tx)
// 	assert.Error(t, err)
// }

// func TestGetTransaction(t *testing.T) {
// 	// Create a temporary directory for the test database
// 	tempDir, err := os.MkdirTemp("", "txpool_test")
// 	assert.NoError(t, err)

// 	// Clean up the temporary directory after the test completes
// 	defer os.RemoveAll(tempDir)

// 	// Create the database directly for the test
// 	db, err := store.NewDatabase(tempDir)
// 	assert.NoError(t, err)
// 	defer db.Close()

// 	// Create a proper private key for testing
// 	privKey, err := crypto.NewPrivateKey()
// 	assert.NoError(t, err)

// 	// Create a minimal blockchain config for testing
// 	config := &types.BlockchainConfig{
// 		DataDir:        tempDir,
// 		GenesisAccount: privKey,
// 		TestMode:       true,
// 	}

// 	// Create the blockchain using the NewBlockchain constructor
// 	blockchain, _, err := chain.NewBlockchain(config)
// 	assert.NoError(t, err)

// 	// Now create the transaction pool with the required arguments
// 	pool := chain.NewTxPool(db, blockchain)
// 	tx := &types.Transaction{ID: "tx1"}

// 	// Add a transaction
// 	err = pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	// Retrieve the transaction by ID
// 	retrievedTx, err := pool.GetTransaction("tx1")
// 	assert.NoError(t, err)
// 	assert.Equal(t, tx, retrievedTx)

// 	// Try getting a non-existent transaction - should error
// 	_, err = pool.GetTransaction("tx2")
// 	assert.Error(t, err)
// }

// func TestGetAllTransactions(t *testing.T) {
// 	// Create a temporary directory for the test database
// 	tempDir, err := os.MkdirTemp("", "txpool_test")
// 	assert.NoError(t, err)

// 	// Clean up the temporary directory after the test completes
// 	defer os.RemoveAll(tempDir)

// 	// Create the database directly for the test
// 	db, err := store.NewDatabase(tempDir)
// 	assert.NoError(t, err)
// 	defer db.Close()

// 	// Create a proper private key for testing
// 	privKey, err := crypto.NewPrivateKey()
// 	assert.NoError(t, err)

// 	// Create a minimal blockchain config for testing
// 	config := &types.BlockchainConfig{
// 		DataDir:        tempDir,
// 		GenesisAccount: privKey,
// 		TestMode:       true,
// 	}

// 	// Create the blockchain using the NewBlockchain constructor
// 	blockchain, _, err := chain.NewBlockchain(config)
// 	assert.NoError(t, err)

// 	// Now create the transaction pool with the required arguments
// 	pool := chain.NewTxPool(db, blockchain)

// 	// Create and add two test transactions
// 	tx1 := &types.Transaction{ID: "tx1"}
// 	tx2 := &types.Transaction{ID: "tx2"}

// 	// Add transactions to the pool
// 	err = pool.AddTransaction(tx1)
// 	assert.NoError(t, err)
// 	err = pool.AddTransaction(tx2)
// 	assert.NoError(t, err)

// 	// Retrieve all transactions from the pool
// 	txs, err := pool.GetAllTransactions()
// 	assert.NoError(t, err)

// 	// Verify we got the expected number of transactions
// 	assert.Len(t, txs, 2)

// 	// Verify both transactions are in the returned slice
// 	assert.Contains(t, txs, tx1)
// 	assert.Contains(t, txs, tx2)
// }

// func TestBroadcastTransaction(t *testing.T) {
// 	// Create a temporary directory for the test database
// 	tempDir, err := os.MkdirTemp("", "txpool_test")
// 	assert.NoError(t, err)

// 	// Clean up the temporary directory after the test completes
// 	defer os.RemoveAll(tempDir)

// 	// Create the database directly for the test
// 	db, err := store.NewDatabase(tempDir)
// 	assert.NoError(t, err)
// 	defer db.Close()

// 	// Create a proper private key for testing
// 	privKey, err := crypto.NewPrivateKey()
// 	assert.NoError(t, err)

// 	// Create a minimal blockchain config for testing
// 	config := &types.BlockchainConfig{
// 		DataDir:        tempDir,
// 		GenesisAccount: privKey,
// 		TestMode:       true,
// 	}

// 	// Create the blockchain using the NewBlockchain constructor
// 	blockchain, _, err := chain.NewBlockchain(config)
// 	assert.NoError(t, err)

// 	// Now create the transaction pool with the required arguments
// 	pool := chain.NewTxPool(db, blockchain)

// 	// Create a test transaction
// 	tx := &types.Transaction{ID: "tx1"}

// 	// Test broadcasting the transaction
// 	err = pool.BroadcastTransaction(tx)
// 	assert.NoError(t, err)
// }

// func TestSize(t *testing.T) {
// 	// Create a temporary directory for the test database
// 	tempDir, err := os.MkdirTemp("", "txpool_test")
// 	assert.NoError(t, err)

// 	// Clean up the temporary directory after the test completes
// 	defer os.RemoveAll(tempDir)

// 	// Create the database directly for the test
// 	db, err := store.NewDatabase(tempDir)
// 	assert.NoError(t, err)
// 	defer db.Close()

// 	// Create a proper private key for testing
// 	privKey, err := crypto.NewPrivateKey()
// 	assert.NoError(t, err)

// 	// Create a minimal blockchain config for testing
// 	config := &types.BlockchainConfig{
// 		DataDir:        tempDir,
// 		GenesisAccount: privKey,
// 		TestMode:       true,
// 	}

// 	// Create the blockchain using the NewBlockchain constructor
// 	blockchain, _, err := chain.NewBlockchain(config)
// 	assert.NoError(t, err)

// 	// Now create the transaction pool with the required arguments
// 	pool := chain.NewTxPool(db, blockchain)

// 	// Test initial size should be 0
// 	assert.Equal(t, 0, pool.Size())

// 	// Add a transaction
// 	tx := &types.Transaction{ID: "tx1"}
// 	err = pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	// Size should now be 1
// 	assert.Equal(t, 1, pool.Size())

// 	// Remove the transaction
// 	err = pool.RemoveTransaction(tx)
// 	assert.NoError(t, err)

// 	// Size should be back to 0
// 	assert.Equal(t, 0, pool.Size())
// }
