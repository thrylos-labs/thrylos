package core

import (
	"fmt"
	"hash/fnv"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/state"
	"golang.org/x/crypto/ed25519"
)

func TestNewBlockchain1(t *testing.T) {
	// Use a predefined valid Bech32 address for genesis
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"

	tempDir, err := os.MkdirTemp("", "blockchain-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	blockchain, _, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    genesisAddress,
		TestMode:          true,
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

// Helper function to generate address for specific shard
func generateAddressForShard(shardID int, nonce int, numShards int) string {
	// Use shardID instead of batch calculation
	// Ensures addresses match partition ranges
	return fmt.Sprintf("tl1%02d%s", shardID, fmt.Sprintf("%015x", nonce))
}

func createRealisticTransaction(t *testing.T, blockchain *Blockchain, sender string, nonce int, numShards int) *thrylos.Transaction {
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s-%d", sender, nonce)))
	shardID := int(h.Sum32() % uint32(numShards))

	recipientAddress := generateAddressForShard(shardID, nonce, numShards)

	// Rest of the function remains the same
	inputAmount := int64(5000 + (nonce % 1000))
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
				OwnerAddress: recipientAddress,
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

// Define the metrics struct
type ShardMetrics struct {
	accesses int64
	modifies int64
}

type ShardMetricsData struct {
	AccessCount  int64
	ModifyCount  int64
	TotalTxCount int64
	AvgLatency   time.Duration
	LoadFactor   float64
}

func TestRealisticBlockTimeToFinalityWithShardingAndBatching(t *testing.T) {
	// Create test directory
	tempDir, err := os.MkdirTemp("", "blockchain-production-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	// Production-like timing constants
	const (
		networkLatency    = 25 * time.Millisecond  // Reduced from 75ms
		consensusDelay    = 100 * time.Millisecond // Reduced from 200ms
		validatorCount    = 16
		txsPerBlock       = 1000
		batchSize         = 50 // Smaller batches for better distribution
		batchDelay        = 30 * time.Millisecond
		expectedBlockTime = 850 * time.Millisecond
		numShards         = 12
	)

	// Initialize network handler mock
	networkHandler := state.NewMockNetworkInterface(networkLatency, 0.1)

	// Initialize state manager with sharding
	stateManager := state.NewStateManager(networkHandler, numShards)
	defer stateManager.StopStateSyncLoop()

	// Initialize blockchain with genesis account and state manager
	genesisAddress := "tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq"
	blockchain, _, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    genesisAddress,
		TestMode:          true,
		DisableBackground: true,
		StateManager:      stateManager,
	})
	require.NoError(t, err, "Failed to create blockchain")

	// Initialize batch processor
	node := &Node{
		Blockchain:   blockchain,
		BlockTrigger: make(chan struct{}, 1), // Add this
	}

	// Initialize DAG Manager first
	node.DAGManager = NewDAGManager(node)

	// Initialize ModernProcessor instead of BatchProcessor
	node.ModernProcessor = NewModernProcessor(node)
	node.ModernProcessor.Start()

	// Setup validators (same as before)
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

		err = blockchain.Database.InsertOrUpdateEd25519PublicKey(address, publicKey)
		require.NoError(t, err, "Failed to store validator public key")
		err = blockchain.ValidatorKeys.StoreKey(address, privateKey)
		require.NoError(t, err, "Failed to store validator private key")
		blockchain.PublicKeyMap[address] = publicKey

		err = stateManager.UpdateState(address, 1000000, nil)
		require.NoError(t, err, "Failed to initialize validator state")
	}

	// Test cases for different network loads
	testCases := []struct {
		name            string
		numBlocks       int
		networkLoad     string
		latencyFactor   float64
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

			shardMetrics := make(map[int]*ShardMetricsData)
			for i := 0; i < numShards; i++ {
				shardMetrics[i] = &ShardMetricsData{}
			}

			startTime := time.Now()

			blockchain.Mu.RLock()
			initialHeight := len(blockchain.Blocks)
			prevHash := blockchain.Blocks[len(blockchain.Blocks)-1].Hash
			blockchain.Mu.RUnlock()

			// Process blocks
			for i := 0; i < tc.numBlocks; i++ {
				blockStart := time.Now()

				// Pre-allocate transaction slice with capacity
				allTxs := make([]*thrylos.Transaction, 0, txsPerBlock)

				// Create channels
				txChan := make(chan *thrylos.Transaction, txsPerBlock)
				resultChan := make(chan struct {
					tx      *thrylos.Transaction
					latency time.Duration
				}, txsPerBlock)

				// Create metrics channel
				metricsChan := make(chan struct {
					shardID int
					latency time.Duration
				}, txsPerBlock)

				var wg sync.WaitGroup
				parallelism := runtime.NumCPU() * 6 // Increase from 4x to 6x

				// Launch processor goroutines
				for w := 0; w < parallelism; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for tx := range txChan {
							start := time.Now()
							err := node.ProcessIncomingTransaction(tx)
							require.NoError(t, err)

							resultChan <- struct {
								tx      *thrylos.Transaction
								latency time.Duration
							}{tx, time.Since(start)}
						}
					}()
				}

				// Launch metrics collector
				go func() {
					for metric := range metricsChan {
						metrics := shardMetrics[metric.shardID]
						metrics.ModifyCount++
						metrics.TotalTxCount++
						if metrics.AvgLatency == 0 {
							metrics.AvgLatency = metric.latency
						} else {
							metrics.AvgLatency = (metrics.AvgLatency + metric.latency) / 2
						}
						metrics.LoadFactor = float64(metrics.TotalTxCount) / float64(txsPerBlock*tc.numBlocks/numShards)
					}
				}()

				// Feed transactions to workers
				go func() {
					for j := 0; j < txsPerBlock; j++ {
						tx := createRealisticTransaction(t, blockchain, genesisAddress, j, numShards)
						txChan <- tx
					}
					close(txChan)
				}()

				// Collect results
				go func() {
					for result := range resultChan {
						tx := result.tx
						allTxs = append(allTxs, tx)
						batchTimes = append(batchTimes, result.latency)

						// Update metrics
						for _, output := range tx.Outputs {
							partition := stateManager.GetResponsiblePartition(output.OwnerAddress)
							if partition != nil {
								metricsChan <- struct {
									shardID int
									latency time.Duration
								}{partition.ID, result.latency}

								err := stateManager.UpdateState(output.OwnerAddress, output.Amount, nil)
								require.NoError(t, err)
							}
						}
					}
					close(metricsChan)
				}()

				// Wait for all processors to complete
				wg.Wait()
				close(resultChan)

				// Create and process block
				validatorIndex := i % validatorCount
				currentValidator := validators[validatorIndex]
				time.Sleep(consensusDelay)

				block := &Block{
					Index:        int32(initialHeight + i),
					Timestamp:    time.Now().Unix(),
					Transactions: allTxs,
					Validator:    currentValidator.address,
					PrevHash:     prevHash,
				}

				err := block.InitializeVerkleTree()
				require.NoError(t, err)

				block.Hash = block.ComputeHash()
				block.Signature = ed25519.Sign(currentValidator.privateKey, block.Hash)

				blockchain.Mu.Lock()
				blockchain.Blocks = append(blockchain.Blocks, block)
				blockchain.Mu.Unlock()

				prevHash = block.Hash
				blockTime := time.Since(blockStart)
				blockTimes = append(blockTimes, blockTime)

				t.Logf("Block %d total creation time: %v", i, blockTime)
			}

			// Calculate and log metrics (same as before)
			t.Logf("\nDetailed Shard Distribution Analysis:")
			var totalTxs int64
			var maxLoad, minLoad float64 = 0, 1

			for shardID, metrics := range shardMetrics {
				totalTxs += metrics.TotalTxCount
				if metrics.LoadFactor > maxLoad {
					maxLoad = metrics.LoadFactor
				}
				if metrics.LoadFactor < minLoad {
					minLoad = metrics.LoadFactor
				}
				t.Logf("Shard %d:\n"+
					"  - Total Transactions: %d\n"+
					"  - Modifications: %d\n"+
					"  - Average Latency: %v\n"+
					"  - Load Factor: %.2f",
					shardID, metrics.TotalTxCount, metrics.ModifyCount,
					metrics.AvgLatency, metrics.LoadFactor)
			}

			loadImbalance := maxLoad - minLoad
			t.Logf("\nLoad Distribution Metrics:")
			t.Logf("- Maximum Load Factor: %.2f", maxLoad)
			t.Logf("- Minimum Load Factor: %.2f", minLoad)
			t.Logf("- Load Imbalance: %.2f", loadImbalance)
			t.Logf("- Average Transactions per Shard: %.2f", float64(totalTxs)/float64(numShards))

			// Convert metrics for legacy format
			legacyMetrics := make(map[int]struct {
				accesses int64
				modifies int64
			})
			for shardID, metrics := range shardMetrics {
				legacyMetrics[shardID] = struct {
					accesses int64
					modifies int64
				}{
					accesses: metrics.AccessCount,
					modifies: metrics.ModifyCount,
				}
			}

			calculateAndLogMetrics(t, tc.name, blockTimes, batchTimes, legacyMetrics,
				startTime, txsPerBlock, expectedBlockTime, tc.expectedMaxTime)

			t.Logf("\nPredictive Scaling Metrics:")
			for shardID := range shardMetrics {
				history := stateManager.Predictive.HistoricalLoad[shardID]
				if history != nil {
					prediction := stateManager.Predictive.CalculateTrend(history)
					currentLoad := shardMetrics[shardID].LoadFactor
					scalingNeeded := prediction > stateManager.Predictive.ScalingThreshold
					t.Logf("Shard %d:\n"+
						"  - Current Load: %.2f\n"+
						"  - Predicted Load: %.2f\n"+
						"  - Scaling Needed: %v",
						shardID, currentLoad, prediction, scalingNeeded)
				}
			}
		})

		time.Sleep(500 * time.Millisecond)
	}
}

// Helper function to calculate and log metrics
func calculateAndLogMetrics(t *testing.T, testName string, blockTimes, batchTimes []time.Duration,
	shardMetrics map[int]struct{ accesses, modifies int64 }, startTime time.Time,
	txsPerBlock int, expectedBlockTime, expectedMaxTime time.Duration) {

	var totalBlockTime, maxBlockTime time.Duration
	var minBlockTime = time.Hour
	var totalBatchTime, maxBatchTime time.Duration
	var minBatchTime = time.Hour

	// Calculate block timing metrics
	for _, bt := range blockTimes {
		totalBlockTime += bt
		if bt > maxBlockTime {
			maxBlockTime = bt
		}
		if bt < minBlockTime {
			minBlockTime = bt
		}
	}

	// Calculate batch timing metrics
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
	t.Logf("\nDetailed metrics for %s:", testName)
	t.Logf("Average block time: %v", avgBlockTime)
	t.Logf("Minimum block time: %v", minBlockTime)
	t.Logf("Maximum block time: %v", maxBlockTime)
	t.Logf("Average batch time: %v", avgBatchTime)
	t.Logf("Minimum batch time: %v", minBatchTime)
	t.Logf("Maximum batch time: %v", maxBatchTime)
	t.Logf("Total processing time: %v", totalTime)
	t.Logf("Transactions processed: %d", len(blockTimes)*txsPerBlock)
	t.Logf("Average TPS: %.2f", float64(len(blockTimes)*txsPerBlock)/totalTime.Seconds())
	t.Logf("Effective batch TPS: %.2f", float64(txsPerBlock)/avgBatchTime.Seconds())

	// Log shard-specific metrics
	t.Logf("\nShard metrics:")
	for shardID, metrics := range shardMetrics {
		t.Logf("Shard %d - Accesses: %d, Modifications: %d",
			shardID, metrics.accesses, metrics.modifies)
	}

	// Verify expectations
	require.Less(t, avgBlockTime, 2*expectedBlockTime,
		"Average block time exceeds twice the target block time")
	require.Less(t, totalTime, expectedMaxTime,
		"Total processing time exceeds maximum allowed time")
}
