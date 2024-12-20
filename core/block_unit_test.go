package core

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/supabase-go"
	thrylos "github.com/thrylos-labs/thrylos"
	"golang.org/x/crypto/ed25519"
)

func TestNewBlockchain1(t *testing.T) {
	// Use a predefined valid Bech32 address for genesis
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"

	// Other test setup remains the same
	mockSupabaseClient := &supabase.Client{}

	tempDir, err := os.MkdirTemp("", "blockchain-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	blockchain, _, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    genesisAddress,
		TestMode:          true,
		SupabaseClient:    mockSupabaseClient,
		DisableBackground: true,
	})
	require.NoError(t, err, "Failed to create blockchain")

	// Additional assertions
	require.NotNil(t, blockchain, "Blockchain should not be nil")
	require.Equal(t, genesisAddress, blockchain.GenesisAccount, "Genesis account should match")
	require.Greater(t, len(blockchain.ActiveValidators), 0, "Should have active validators")
}

// Helper function to handle block creation and signing
func createAndSignBlock(t *testing.T, blockchain *Blockchain, txs []*thrylos.Transaction, validator string, validatorKey ed25519.PrivateKey, prevHash []byte) error {
	// Create block
	block := &Block{
		Index:        int32(len(blockchain.Blocks)),
		Timestamp:    time.Now().Unix(),
		Transactions: txs,
		Validator:    validator,
		PrevHash:     prevHash,
	}

	// Initialize Verkle tree
	if err := block.InitializeVerkleTree(); err != nil {
		return fmt.Errorf("failed to initialize Verkle tree: %v", err)
	}

	// Compute hash
	block.Hash = block.ComputeHash()

	// Sign block
	signature := ed25519.Sign(validatorKey, block.Hash)
	block.Signature = signature

	// Add block to blockchain
	blockchain.Mu.Lock()
	blockchain.Blocks = append(blockchain.Blocks, block)
	blockchain.Mu.Unlock()

	return nil
}

func TestBlockTimeToFinality(t *testing.T) {
	// Create test directory
	tempDir, err := os.MkdirTemp("", "blockchain-finality-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Use predefined genesis account
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"

	// Initialize blockchain
	blockchain, _, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    genesisAddress,
		TestMode:          true,
		DisableBackground: true,
	})
	require.NoError(t, err, "Failed to create blockchain")

	// Generate and store test keys
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate key pair")

	err = blockchain.Database.InsertOrUpdateEd25519PublicKey(genesisAddress, publicKey)
	require.NoError(t, err, "Failed to store public key")

	err = blockchain.ValidatorKeys.StoreKey(genesisAddress, privateKey)
	require.NoError(t, err, "Failed to store private key")

	blockchain.PublicKeyMap[genesisAddress] = publicKey

	// Get genesis transaction
	blockchain.Mu.RLock()
	genesisTx := blockchain.Blocks[0].Transactions[0]
	blockchain.Mu.RUnlock()
	require.NotNil(t, genesisTx, "Genesis transaction should exist")

	// Test cases
	testCases := []struct {
		name       string
		numBlocks  int
		maxAvgTime time.Duration
		maxTotal   time.Duration
	}{
		{
			name:       "Small Network",
			numBlocks:  5,
			maxAvgTime: 2 * time.Second,
			maxTotal:   10 * time.Second,
		},
		{
			name:       "Medium Network",
			numBlocks:  10,
			maxAvgTime: 1 * time.Second,
			maxTotal:   20 * time.Second,
		},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			var blockTimes []time.Duration
			startTime := time.Now()

			// Get initial previous hash
			blockchain.Mu.RLock()
			prevHash := blockchain.Blocks[len(blockchain.Blocks)-1].Hash
			blockchain.Mu.RUnlock()

			// Create blocks
			for i := 0; i < tc.numBlocks; i++ {
				// Create transaction
				gasAmount := int32(BaseGasFee)
				inputAmount := int64(2000)
				outputAmount := inputAmount - int64(gasAmount)

				tx := &thrylos.Transaction{
					Id:        fmt.Sprintf("test-tx-%d", i),
					Timestamp: time.Now().Unix(),
					Sender:    genesisAddress,
					Gasfee:    gasAmount,
					Inputs: []*thrylos.UTXO{
						{
							TransactionId: genesisTx.Id,
							Index:         int32(i),
							OwnerAddress:  genesisAddress,
							Amount:        inputAmount,
						},
					},
					Outputs: []*thrylos.UTXO{
						{
							OwnerAddress: genesisAddress,
							Amount:       outputAmount,
							Index:        0,
						},
					},
				}

				// Sign transaction
				signData := []byte(fmt.Sprintf("%s%d%s%d",
					tx.Id, tx.Timestamp, tx.Sender, tx.Gasfee))
				for _, input := range tx.Inputs {
					signData = append(signData, []byte(fmt.Sprintf("%s%d%s%d",
						input.TransactionId, input.Index,
						input.OwnerAddress, input.Amount))...)
				}
				for _, output := range tx.Outputs {
					signData = append(signData, []byte(fmt.Sprintf("%s%d%d",
						output.OwnerAddress, output.Index,
						output.Amount))...)
				}

				tx.Signature = ed25519.Sign(privateKey, signData)

				// Create and sign block
				blockStart := time.Now()
				err := createAndSignBlock(t, blockchain, []*thrylos.Transaction{tx}, genesisAddress, privateKey, prevHash)
				require.NoError(t, err, fmt.Sprintf("Failed to create block %d", i))
				blockTime := time.Since(blockStart)

				// Update previous hash
				blockchain.Mu.RLock()
				prevHash = blockchain.Blocks[len(blockchain.Blocks)-1].Hash
				blockchain.Mu.RUnlock()

				blockTimes = append(blockTimes, blockTime)
			}

			// Calculate metrics
			var totalBlockTime time.Duration
			for _, bt := range blockTimes {
				totalBlockTime += bt
			}

			avgBlockTime := totalBlockTime / time.Duration(len(blockTimes))
			totalTime := time.Since(startTime)

			// Log metrics
			t.Logf("Performance metrics for %s:", tc.name)
			t.Logf("Average block time: %v", avgBlockTime)
			t.Logf("Total time: %v", totalTime)

			// Verify expectations
			if avgBlockTime >= tc.maxAvgTime {
				t.Errorf("Average block time %v exceeds maximum %v",
					avgBlockTime, tc.maxAvgTime)
			}
			if totalTime >= tc.maxTotal {
				t.Errorf("Total time %v exceeds maximum %v",
					totalTime, tc.maxTotal)
			}
		})

		// Allow cleanup between test cases
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRealisticBlockTimeToFinality(t *testing.T) {
	// Create test directory
	tempDir, err := os.MkdirTemp("", "blockchain-production-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Production-like timing constants
	const (
		networkLatency    = 100 * time.Millisecond  // Average network latency
		consensusDelay    = 300 * time.Millisecond  // Time for consensus
		validatorCount    = 4                       // Number of active validators
		txsPerBlock       = 100                     // Total transactions per block
		batchSize         = 25                      // Transactions per batch
		batchDelay        = 50 * time.Millisecond   // Delay between batch processing
		expectedBlockTime = 1200 * time.Millisecond // Target block time (1.2s)
	)

	// Initialize blockchain with genesis account
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"
	blockchain, _, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    genesisAddress,
		TestMode:          true,
		DisableBackground: true,
	})
	require.NoError(t, err, "Failed to create blockchain")

	// Setup validators
	validators := make([]struct {
		address    string
		publicKey  ed25519.PublicKey
		privateKey ed25519.PrivateKey
	}, validatorCount)

	// Create and register validators
	for i := 0; i < validatorCount; i++ {
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err, "Failed to generate validator key pair")

		address := fmt.Sprintf("tl11validator%d", i)
		validators[i] = struct {
			address    string
			publicKey  ed25519.PublicKey
			privateKey ed25519.PrivateKey
		}{
			address:    address,
			publicKey:  publicKey,
			privateKey: privateKey,
		}

		// Register validator
		err = blockchain.Database.InsertOrUpdateEd25519PublicKey(address, publicKey)
		require.NoError(t, err, "Failed to store validator public key")
		err = blockchain.ValidatorKeys.StoreKey(address, privateKey)
		require.NoError(t, err, "Failed to store validator private key")
		blockchain.PublicKeyMap[address] = publicKey
	}

	// Test cases for different network loads
	testCases := []struct {
		name            string
		numBlocks       int
		networkLoad     string
		latencyFactor   float64 // Multiplier for network latency
		expectedMaxTime time.Duration
	}{
		{
			name:            "Normal Network Load",
			numBlocks:       10,
			networkLoad:     "normal",
			latencyFactor:   1.0,
			expectedMaxTime: 15 * time.Second,
		},
		{
			name:            "High Network Load",
			numBlocks:       10,
			networkLoad:     "high",
			latencyFactor:   2.0,
			expectedMaxTime: 25 * time.Second,
		},
		{
			name:            "Peak Network Load",
			numBlocks:       10,
			networkLoad:     "peak",
			latencyFactor:   3.0,
			expectedMaxTime: 35 * time.Second,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var blockTimes []time.Duration
			var batchTimes []time.Duration
			startTime := time.Now()

			// Get initial blockchain state
			blockchain.Mu.RLock()
			initialHeight := len(blockchain.Blocks)
			prevHash := blockchain.Blocks[len(blockchain.Blocks)-1].Hash
			blockchain.Mu.RUnlock()

			// Process blocks
			for i := 0; i < tc.numBlocks; i++ {
				blockStart := time.Now()

				// Process transactions in batches
				var allTxs []*thrylos.Transaction
				numBatches := txsPerBlock / batchSize

				for b := 0; b < numBatches; b++ {
					batchStart := time.Now()

					// Create batch of transactions
					var batchTxs []*thrylos.Transaction
					startIdx := b * batchSize
					endIdx := startIdx + batchSize

					for j := startIdx; j < endIdx; j++ {
						tx := createRealisticTransaction(t, blockchain, genesisAddress, i*txsPerBlock+j)
						batchTxs = append(batchTxs, tx)
					}

					// Simulate batch processing time with network latency
					time.Sleep(time.Duration(float64(networkLatency) * tc.latencyFactor / float64(numBatches)))

					// Simulate batch processing overhead
					time.Sleep(batchDelay)

					allTxs = append(allTxs, batchTxs...)

					batchTime := time.Since(batchStart)
					batchTimes = append(batchTimes, batchTime)
					t.Logf("Block %d - Batch %d processing time: %v", i, b+1, batchTime)
				}

				// Simulate consensus process
				validatorIndex := i % validatorCount
				currentValidator := validators[validatorIndex]

				// Simulate validator signing with consensus delay
				time.Sleep(consensusDelay)

				// Create block with all accumulated transactions
				block := &Block{
					Index:        int32(initialHeight + i),
					Timestamp:    time.Now().Unix(),
					Transactions: allTxs,
					Validator:    currentValidator.address,
					PrevHash:     prevHash,
				}

				// Initialize Verkle tree
				err := block.InitializeVerkleTree()
				require.NoError(t, err, "Failed to initialize Verkle tree")

				// Compute and sign block
				block.Hash = block.ComputeHash()
				block.Signature = ed25519.Sign(currentValidator.privateKey, block.Hash)

				// Add block to chain
				blockchain.Mu.Lock()
				blockchain.Blocks = append(blockchain.Blocks, block)
				blockchain.Mu.Unlock()

				prevHash = block.Hash
				blockTime := time.Since(blockStart)
				blockTimes = append(blockTimes, blockTime)

				// Log individual block metrics
				t.Logf("Block %d total creation time: %v", i, blockTime)
			}

			// Calculate and validate metrics
			var totalBlockTime time.Duration
			var maxBlockTime time.Duration
			var minBlockTime = time.Hour
			var totalBatchTime time.Duration
			var maxBatchTime time.Duration
			var minBatchTime = time.Hour

			for _, bt := range blockTimes {
				totalBlockTime += bt
				if bt > maxBlockTime {
					maxBlockTime = bt
				}
				if bt < minBlockTime {
					minBlockTime = bt
				}
			}

			for _, bt := range batchTimes {
				totalBatchTime += bt
				if bt > maxBatchTime {
					maxBatchTime = bt
				}
				if bt < minBatchTime {
					minBatchTime = bt
				}
			}

			avgBlockTime := totalBlockTime / time.Duration(len(blockTimes))
			avgBatchTime := totalBatchTime / time.Duration(len(batchTimes))
			totalTime := time.Since(startTime)

			// Log comprehensive metrics
			t.Logf("\nDetailed metrics for %s:", tc.name)
			t.Logf("Average block time: %v", avgBlockTime)
			t.Logf("Minimum block time: %v", minBlockTime)
			t.Logf("Maximum block time: %v", maxBlockTime)
			t.Logf("Average batch time: %v", avgBatchTime)
			t.Logf("Minimum batch time: %v", minBatchTime)
			t.Logf("Maximum batch time: %v", maxBatchTime)
			t.Logf("Total processing time: %v", totalTime)
			t.Logf("Transactions processed: %d", tc.numBlocks*txsPerBlock)
			t.Logf("Average TPS: %.2f", float64(tc.numBlocks*txsPerBlock)/totalTime.Seconds())
			t.Logf("Effective batch TPS: %.2f", float64(batchSize)/avgBatchTime.Seconds())

			// Verify expectations
			require.Less(t, avgBlockTime, 2*expectedBlockTime,
				"Average block time exceeds twice the target block time")
			require.Less(t, totalTime, tc.expectedMaxTime,
				"Total processing time exceeds maximum allowed time")
		})

		// Allow cleanup between test cases
		time.Sleep(500 * time.Millisecond)
	}
}

// Helper function to create a realistic transaction
func createRealisticTransaction(t *testing.T, blockchain *Blockchain, sender string, nonce int) *thrylos.Transaction {
	// Realistic transaction amounts (in the thousands range)
	inputAmount := int64(5000 + (nonce % 1000)) // Varying amounts
	gasAmount := int32(BaseGasFee)
	outputAmount := inputAmount - int64(gasAmount)

	tx := &thrylos.Transaction{
		Id:        fmt.Sprintf("tx-%d-%d", time.Now().UnixNano(), nonce),
		Timestamp: time.Now().Unix(),
		Sender:    sender,
		Gasfee:    gasAmount,
		Inputs: []*thrylos.UTXO{
			{
				TransactionId: fmt.Sprintf("prev-tx-%d", nonce),
				Index:         int32(nonce),
				OwnerAddress:  sender,
				Amount:        inputAmount,
			},
		},
		Outputs: []*thrylos.UTXO{
			{
				OwnerAddress: fmt.Sprintf("recipient-%d", nonce%100), // Simulate multiple recipients
				Amount:       outputAmount,
				Index:        0,
			},
		},
	}

	// Create signature data
	signData := createSignatureData(tx)

	// Get sender's private key
	privateKey, exists := blockchain.ValidatorKeys.GetKey(sender)
	require.True(t, exists, "Failed to get sender's private key")

	// Sign transaction
	tx.Signature = ed25519.Sign(privateKey, signData)
	return tx
}

// Helper function to create signature data
func createSignatureData(tx *thrylos.Transaction) []byte {
	signData := []byte(fmt.Sprintf("%s%d%s%d",
		tx.Id, tx.Timestamp, tx.Sender, tx.Gasfee))

	for _, input := range tx.Inputs {
		signData = append(signData, []byte(fmt.Sprintf("%s%d%s%d",
			input.TransactionId, input.Index,
			input.OwnerAddress, input.Amount))...)
	}

	for _, output := range tx.Outputs {
		signData = append(signData, []byte(fmt.Sprintf("%s%d%d",
			output.OwnerAddress, output.Index,
			output.Amount))...)
	}

	return signData
}
