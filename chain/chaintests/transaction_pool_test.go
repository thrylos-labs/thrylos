package chaintests

// func TestAddTransaction(t *testing.T) {
// 	pool := chain.NewTxPool()
// 	tx := &shared.Transaction{ID: "tx1"}

// 	err := pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	// Try adding the same transaction again
// 	err = pool.AddTransaction(tx)
// 	assert.Error(t, err)
// }

// func TestRemoveTransaction(t *testing.T) {
// 	pool := chain.NewTxPool()
// 	tx := &shared.Transaction{ID: "tx1"}

// 	err := pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	err = pool.RemoveTransaction(tx)
// 	assert.NoError(t, err)

// 	// Try removing the same transaction again
// 	err = pool.RemoveTransaction(tx)
// 	assert.Error(t, err)
// }

// func TestGetTransaction(t *testing.T) {
// 	pool := chain.NewTxPool()
// 	tx := &shared.Transaction{ID: "tx1"}

// 	err := pool.AddTransaction(tx)
// 	assert.NoError(t, err)

// 	retrievedTx, err := pool.GetTransaction("tx1")
// 	assert.NoError(t, err)
// 	assert.Equal(t, tx, retrievedTx)

// 	// Try getting a non-existent transaction
// 	_, err = pool.GetTransaction("tx2")
// 	assert.Error(t, err)
// }

// func TestGetAllTransactions(t *testing.T) {
// 	pool := chain.NewTxPool()
// 	tx1 := &shared.Transaction{ID: "tx1"}
// 	tx2 := &shared.Transaction{ID: "tx2"}

// 	err := pool.AddTransaction(tx1)
// 	assert.NoError(t, err)
// 	err = pool.AddTransaction(tx2)
// 	assert.NoError(t, err)

// 	txs, err := pool.GetAllTransactions()
// 	assert.NoError(t, err)
// 	assert.Len(t, txs, 2)
// 	assert.Contains(t, txs, tx1)
// 	assert.Contains(t, txs, tx2)
// }

// func TestBroadcastTransaction(t *testing.T) {
// 	pool := chain.NewTxPool()
// 	tx := &shared.Transaction{ID: "tx1"}

// 	err := pool.BroadcastTransaction(tx)
// 	assert.NoError(t, err)
// }

// func TestSize(t *testing.T) {
// 	pool := chain.NewTxPool()
// 	assert.Equal(t, 0, pool.Size())

// 	tx := &shared.Transaction{ID: "tx1"}
// 	err := pool.AddTransaction(tx)
// 	assert.NoError(t, err)
// 	assert.Equal(t, 1, pool.Size())

// 	err = pool.RemoveTransaction(tx)
// 	assert.NoError(t, err)
// 	assert.Equal(t, 0, pool.Size())
// }
