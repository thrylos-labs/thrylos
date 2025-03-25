package chaintests

import (
	"crypto/rand"
	"fmt"
	"hash/fnv"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/chain"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

// // Helper function to handle block creation and signing
func createAndSignBlock(t *testing.T, blockchain *types.Blockchain, txs []*thrylos.Transaction, validatorKey *crypto.PrivateKey, prevHash []byte) error {
	// Convert transactions using existing function
	sharedTxs := make([]*types.Transaction, len(txs))
	for i, tx := range txs {
		sharedTxs[i] = utils.ConvertToSharedTransaction(tx)
	}

	// Rest of the function remains the same...
	blockHash, err := hash.FromBytes(prevHash)
	if err != nil {
		return fmt.Errorf("failed to create hash from previous hash bytes: %v", err)
	}

	// Create block with proper types
	block := &types.Block{
		Index:              int64(len(blockchain.Blocks)),
		Timestamp:          time.Now().Unix(),
		Transactions:       sharedTxs,
		PrevHash:           blockHash,
		ValidatorPublicKey: nil, // This needs to be set based on your requirements
	}

	// Rest of the implementation remains the same...
	if err := chain.InitializeVerkleTree(block); err != nil {
		return fmt.Errorf("failed to initialize Verkle tree: %v", err)
	}

	chain.ComputeBlockHash(block)

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate signature salt: %v", err)
	}
	signatureData := append(block.Hash[:], salt...)

	//*validatorKey
	signature := (*validatorKey).Sign(signatureData)

	// Assign the signature object directly since it implements crypto.Signature
	block.Signature = signature
	block.Salt = salt

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
	privKey, err := crypto.NewPrivateKey()
	require.NoError(t, err, "Failed to generate private key")
	pubKey := privKey.PublicKey()
	genesisAddress, err := privKey.PublicKey().Address()
	require.NoError(t, err, "Failed to get genesis address")

	// Initialize blockchain
	config := &types.BlockchainConfig{
		DataDir:           tempDir,
		AESKey:            []byte("test-key"),
		GenesisAccount:    privKey,
		TestMode:          true,
		DisableBackground: true,
	}

	blockchainImpl, store, err := chain.NewBlockchain(config)
	require.NoError(t, err, "Failed to create blockchain")

	// Use store instead of letting it go unused
	err = store.SavePublicKey(pubKey)
	require.NoError(t, err, "Failed to store MLDSA public key")

	// Reference the blockchain field from the implementation
	blockchain := blockchainImpl.Blockchain

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
				gasAmount := int32(processor.BaseGasFee)
				inputAmount := int64(2000)
				outputAmount := inputAmount - int64(gasAmount)

				tx := &thrylos.Transaction{
					Id:        fmt.Sprintf("test-tx-%d", i),
					Timestamp: time.Now().Unix(),
					Sender:    genesisAddress.String(),
					Gasfee:    gasAmount,
					Inputs: []*thrylos.UTXO{
						{
							TransactionId: genesisTx.ID,
							Index:         int32(i),
							OwnerAddress:  genesisAddress.String(),
							Amount:        inputAmount,
						},
					},
					Outputs: []*thrylos.UTXO{
						{
							OwnerAddress: genesisAddress.String(),
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

				signature := privKey.Sign(signData)
				require.NoError(t, err, "Failed to sign transaction")
				tx.Signature = signature.Bytes()

				// Create and sign block
				blockStart := time.Now()

				// Convert hash.Hash to []byte
				prevHashBytes := prevHash.Bytes() // Assuming Hash type has a Bytes() method

				//b:= (blockchain).(*shared.Blockchain)
				err = createAndSignBlock(t, blockchain, []*thrylos.Transaction{tx}, &privKey, prevHashBytes)
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

// // Helper function to generate address for specific shard
func generateAddressForShard(shardID int, nonce int, numShards int) string {
	// Use shardID instead of batch calculation
	// Ensures addresses match partition ranges
	return fmt.Sprintf("tl1%02d%s", shardID, fmt.Sprintf("%015x", nonce))
}

func createRealisticTransaction(t *testing.T, blockchain *types.Blockchain, sender string, nonce int, numShards int) *thrylos.Transaction {
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s-%d", sender, nonce)))
	shardID := int(h.Sum32() % uint32(numShards))

	recipientAddress := generateAddressForShard(shardID, nonce, numShards)

	// Rest of the function remains the same
	inputAmount := int64(5000 + (nonce % 1000))
	gasAmount := int32(processor.BaseGasFee)
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
	mldsaPrivKey, exists := blockchain.ValidatorKeys.GetKey(sender)
	require.True(t, exists, "Failed to get sender's private key")

	// Sign using the correct method signature
	signature := (*mldsaPrivKey).Sign(signData)
	require.NotNil(t, signature, "Failed to sign transaction")

	tx.Signature = signature.Bytes() // Using the Bytes() method to get the raw signature
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

func getScalingAction(needsSplit, needsMerge bool) string {
	if needsSplit {
		return "Split"
	}
	if needsMerge {
		return "Merge"
	}
	return "None"
}

// func TestRealisticBlockTimeToFinalityWithShardingAndBatching(t *testing.T) {
// 	// Create test directory
// 	tempDir, err := os.MkdirTemp("", "blockchain-production-test-")
// 	require.NoError(t, err, "Failed to create temp directory")
// 	defer os.RemoveAll(tempDir)

// 	// Production-like timing constants
// 	const (
// 		networkLatency    = 25 * time.Millisecond  // Reduced from 75ms
// 		consensusDelay    = 100 * time.Millisecond // Reduced from 200ms
// 		validatorCount    = 16
// 		txsPerBlock       = 1000
// 		batchSize         = 50 // Smaller batches for better distribution
// 		batchDelay        = 30 * time.Millisecond
// 		expectedBlockTime = 850 * time.Millisecond
// 		numShards         = 12
// 	)

// 	// Initialize network handler mock
// 	networkHandler := state.NewMockNetworkInterface(networkLatency, 0.1)

// 	// Initialize state manager with sharding
// 	stateManager := state.NewStateManager(networkHandler, numShards)
// 	defer stateManager.StopStateSyncLoop()

// 	privKey, err := crypto.NewPrivateKey()
// 	if err != nil {
// 		t.Fatalf("Failed to generate private key: %v", err)
// 	}

// 	// Initialize blockchain with genesis account and state manager
// 	config := &types.BlockchainConfig{
// 		DataDir:           tempDir,
// 		AESKey:            []byte("test-key"),
// 		GenesisAccount:    privKey,
// 		TestMode:          true,
// 		DisableBackground: true,
// 	}

// 	// Create the blockchain
// 	blockchainImpl, store, err := chain.NewBlockchain(config)
// 	require.NoError(t, err, "Failed to create blockchain")

// 	// Create a proper message bus for testing
// 	messageBus := &types.MessageBus{
// 		subscribers: make(map[types.MessageType][]chan types.Message),
// 		mu:          sync.RWMutex{},
// 	}

// 	// Create a node using the constructor to avoid using unexported fields
// 	testNode := node.NewNode("localhost:8080", tempDir)

// 	// Set up the node with the required components
// 	testNode.Mu.Lock()
// 	testNode.blockchain = blockchainImpl.Blockchain // Store the blockchain
// 	blockchain := blockchainImpl.Blockchain         // Create a local reference for easier access
// 	testNode.Database = store

// 	// Use the messageBus we created
// 	testNode.messageBus = messageBus // This fixes the unused variable error

// 	// Create message channel and subscribe it to the messageBus
// 	messageCh := make(chan types.Message, 100)
// 	messageBus.Subscribe(types.ProcessBlock, messageCh)
// 	messageBus.Subscribe(types.ValidateBlock, messageCh)
// 	testNode.messageCh = messageCh
// 	testNode.Mu.Unlock()

// 	// Start a simple message handler for testing
// 	// Instead of calling the unexported handleMessages method
// 	go func() {
// 		for msg := range messageCh {
// 			// Process messages based on type
// 			switch msg.Type {
// 			case types.ProcessBlock:
// 				// Handle block processing
// 				if msg.ResponseCh != nil {
// 					msg.ResponseCh <- types.Response{
// 						Data:  nil,
// 						Error: nil,
// 					}
// 				}
// 			case types.ValidateBlock:
// 				// Handle block validation
// 				if msg.ResponseCh != nil {
// 					msg.ResponseCh <- types.Response{
// 						Data:  true,
// 						Error: nil,
// 					}
// 				}
// 			default:
// 				// Handle other message types as needed
// 				if msg.ResponseCh != nil {
// 					msg.ResponseCh <- types.Response{
// 						Data:  nil,
// 						Error: nil,
// 					}
// 				}
// 			}
// 		}
// 	}()

// 	// Initialize DAG Manager first
// 	dagManager := processor.NewDAGManager()
// 	testNode.Mu.Lock()
// 	testNode.DAGManager = dagManager
// 	testNode.Mu.Unlock()

// 	// Initialize ModernProcessor instead of BatchProcessor
// 	modernProcessor := processor.NewModernProcessor()
// 	modernProcessor.Start()
// 	testNode.Mu.Lock()
// 	testNode.ModernProcessor = modernProcessor
// 	testNode.Mu.Unlock()

// 	// Setup validators
// 	// Setup validators
// 	// Setup validators
// 	validators := make([]struct {
// 		address    string
// 		publicKey  *mldsa44.PublicKey  // Note: Using pointer type
// 		privateKey *mldsa44.PrivateKey // Note: Using pointer type
// 	}, validatorCount)

// 	// Create and register validators
// 	for i := 0; i < validatorCount; i++ {
// 		// GenerateKey returns pointers
// 		publicKey, privateKey, err := mldsa.GenerateKey(nil)
// 		require.NoError(t, err, "Failed to generate validator key pair")

// 		address := fmt.Sprintf("tl11validator%d", i)
// 		validators[i] = struct {
// 			address    string
// 			publicKey  *mldsa44.PublicKey
// 			privateKey *mldsa44.PrivateKey
// 		}{
// 			address:    address,
// 			publicKey:  publicKey,  // Store the pointer directly
// 			privateKey: privateKey, // Store the pointer directly
// 		}

// 		// Make sure we pass the pointers to these functions
// 		err = blockchain.Database.InsertOrUpdateMLDSAPublicKey(address, publicKey)
// 		require.NoError(t, err, "Failed to store validator public key")
// 		err = blockchain.ValidatorKeys.StoreKey(address, privateKey)
// 		require.NoError(t, err, "Failed to store validator private key")
// 		blockchain.PublicKeyMap[address] = publicKey // Store the pointer in the map

// 		err = stateManager.UpdateState(address, 1000000, nil)
// 		require.NoError(t, err, "Failed to initialize validator state")
// 	}

// 	// Test cases for different network loads
// 	testCases := []struct {
// 		name            string
// 		numBlocks       int
// 		networkLoad     string
// 		latencyFactor   float64
// 		expectedMaxTime time.Duration
// 	}{
// 		{
// 			name:            "Normal Network Load",
// 			numBlocks:       10,
// 			networkLoad:     "normal",
// 			latencyFactor:   1.0,
// 			expectedMaxTime: 15 * time.Second,
// 		},
// 		{
// 			name:            "High Network Load",
// 			numBlocks:       10,
// 			networkLoad:     "high",
// 			latencyFactor:   2.0,
// 			expectedMaxTime: 25 * time.Second,
// 		},
// 		{
// 			name:            "Peak Network Load",
// 			numBlocks:       10,
// 			networkLoad:     "peak",
// 			latencyFactor:   3.0,
// 			expectedMaxTime: 35 * time.Second,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		tc := tc
// 		t.Run(tc.name, func(t *testing.T) {
// 			var blockTimes []time.Duration
// 			var batchTimes []time.Duration

// 			shardMetrics := make(map[int]*ShardMetricsData)
// 			for i := 0; i < numShards; i++ {
// 				shardMetrics[i] = &ShardMetricsData{}
// 			}

// 			startTime := time.Now()

// 			blockchain.Mu.RLock()
// 			initialHeight := len(blockchain.Blocks)
// 			prevHash := blockchain.Blocks[len(blockchain.Blocks)-1].Hash
// 			blockchain.Mu.RUnlock()

// 			// Process blocks
// 			for i := 0; i < tc.numBlocks; i++ {
// 				blockStart := time.Now()

// 				// Pre-allocate transaction slice with capacity
// 				allTxs := make([]*thrylos.Transaction, 0, txsPerBlock)

// 				// Create channels
// 				txChan := make(chan *thrylos.Transaction, txsPerBlock)
// 				resultChan := make(chan struct {
// 					tx      *thrylos.Transaction
// 					latency time.Duration
// 				}, txsPerBlock)

// 				// Create metrics channel
// 				metricsChan := make(chan struct {
// 					shardID int
// 					latency time.Duration
// 				}, txsPerBlock)

// 				var wg sync.WaitGroup
// 				parallelism := runtime.NumCPU() * 6

// 				// Launch processor goroutines
// 				for w := 0; w < parallelism; w++ {
// 					wg.Add(1)
// 					go func() {
// 						defer wg.Done()
// 						for tx := range txChan {
// 							start := time.Now()
// 							err := processor.ProcessIncomingTransaction(tx)
// 							require.NoError(t, err)

// 							resultChan <- struct {
// 								tx      *thrylos.Transaction
// 								latency time.Duration
// 							}{tx, time.Since(start)}
// 						}
// 					}()
// 				}

// 				// Launch metrics collector
// 				go func() {
// 					for metric := range metricsChan {
// 						metrics := shardMetrics[metric.shardID]
// 						metrics.ModifyCount++
// 						metrics.TotalTxCount++
// 						if metrics.AvgLatency == 0 {
// 							metrics.AvgLatency = metric.latency
// 						} else {
// 							metrics.AvgLatency = (metrics.AvgLatency + metric.latency) / 2
// 						}
// 						metrics.LoadFactor = float64(metrics.TotalTxCount) / float64(txsPerBlock*tc.numBlocks/numShards)
// 					}
// 				}()

// 				// Feed transactions to workers
// 				go func() {
// 					for j := 0; j < txsPerBlock; j++ {
// 						tx := createRealisticTransaction(t, blockchain, genesisAddress, j, numShards)
// 						txChan <- tx
// 					}
// 					close(txChan)
// 				}()

// 				// Collect results
// 				go func() {
// 					for result := range resultChan {
// 						tx := result.tx
// 						allTxs = append(allTxs, tx)
// 						batchTimes = append(batchTimes, result.latency)

// 						// Update metrics
// 						for _, output := range tx.Outputs {
// 							partition := stateManager.GetResponsiblePartition(output.OwnerAddress)
// 							if partition != nil {
// 								metricsChan <- struct {
// 									shardID int
// 									latency time.Duration
// 								}{partition.ID, result.latency}

// 								err := stateManager.UpdateState(output.OwnerAddress, output.Amount, nil)
// 								require.NoError(t, err)
// 							}
// 						}
// 					}
// 					close(metricsChan)
// 				}()

// 				// Wait for all processors to complete
// 				wg.Wait()
// 				close(resultChan)

// 				// Create and process block
// 				validatorIndex := i % validatorCount
// 				currentValidator := validators[validatorIndex]
// 				time.Sleep(consensusDelay)

// 				block := &types.Block{
// 					Index:        int32(initialHeight + i),
// 					Timestamp:    time.Now().Unix(),
// 					Transactions: allTxs,
// 					Validator:    currentValidator.address,
// 					PrevHash:     prevHash,
// 				}

// 				err := chain.InitializeVerkleTree(block)
// 				require.NoError(t, err)

// 				block.Hash = block.ComputeHash()
// 				block.Signature, err = currentValidator.privateKey.Sign(nil, block.Hash, crypto.Hash(0))
// 				require.NoError(t, err)

// 				blockchain.Mu.Lock()
// 				blockchain.Blocks = append(blockchain.Blocks, block)
// 				blockchain.Mu.Unlock()

// 				prevHash = block.Hash
// 				blockTime := time.Since(blockStart)
// 				blockTimes = append(blockTimes, blockTime)

// 				t.Logf("Block %d total creation time: %v", i, blockTime)
// 			}

// 			// Calculate and log metrics
// 			t.Logf("\nDetailed Shard Distribution Analysis:")
// 			var totalTxs int64
// 			var maxLoad, minLoad float64 = 0, 1

// 			for shardID, metrics := range shardMetrics {
// 				totalTxs += metrics.TotalTxCount
// 				if metrics.LoadFactor > maxLoad {
// 					maxLoad = metrics.LoadFactor
// 				}
// 				if metrics.LoadFactor < minLoad {
// 					minLoad = metrics.LoadFactor
// 				}
// 				t.Logf("Shard %d:\n"+
// 					"  - Total Transactions: %d\n"+
// 					"  - Modifications: %d\n"+
// 					"  - Average Latency: %v\n"+
// 					"  - Load Factor: %.2f",
// 					shardID, metrics.TotalTxCount, metrics.ModifyCount,
// 					metrics.AvgLatency, metrics.LoadFactor)
// 			}

// 			loadImbalance := maxLoad - minLoad
// 			t.Logf("\nLoad Distribution Metrics:")
// 			t.Logf("- Maximum Load Factor: %.2f", maxLoad)
// 			t.Logf("- Minimum Load Factor: %.2f", minLoad)
// 			t.Logf("- Load Imbalance: %.2f", loadImbalance)
// 			t.Logf("- Average Transactions per Shard: %.2f", float64(totalTxs)/float64(numShards))

// 			// Convert metrics for legacy format
// 			legacyMetrics := make(map[int]struct {
// 				accesses int64
// 				modifies int64
// 			})
// 			for shardID, metrics := range shardMetrics {
// 				legacyMetrics[shardID] = struct {
// 					accesses int64
// 					modifies int64
// 				}{
// 					accesses: metrics.AccessCount,
// 					modifies: metrics.ModifyCount,
// 				}
// 			}

// 			calculateAndLogMetrics(t, tc.name, blockTimes, batchTimes, legacyMetrics,
// 				startTime, txsPerBlock, expectedBlockTime, tc.expectedMaxTime)

// 			t.Logf("\nShard Scaling Metrics:")
// 			for shardID := range shardMetrics {
// 				currentLoad := shardMetrics[shardID].LoadFactor
// 				needsSplit := currentLoad > stateManager.Scaling.LoadThresholds.Split
// 				needsMerge := currentLoad < stateManager.Scaling.LoadThresholds.Merge

// 				t.Logf("Shard %d:\n"+
// 					"  - Current Load: %.2f\n"+
// 					"  - Split Threshold: %.2f\n"+
// 					"  - Merge Threshold: %.2f\n"+
// 					"  - Action Needed: %s",
// 					shardID,
// 					currentLoad,
// 					stateManager.Scaling.LoadThresholds.Split,
// 					stateManager.Scaling.LoadThresholds.Merge,
// 					getScalingAction(needsSplit, needsMerge))
// 			}
// 		})

// 		time.Sleep(500 * time.Millisecond)
// 	}
// 	close(messageCh)
// }

// // Helper function to calculate and log metrics
// func calculateAndLogMetrics(t *testing.T, testName string, blockTimes, batchTimes []time.Duration,
// 	shardMetrics map[int]struct{ accesses, modifies int64 }, startTime time.Time,
// 	txsPerBlock int, expectedBlockTime, expectedMaxTime time.Duration) {

// 	var totalBlockTime, maxBlockTime time.Duration
// 	var minBlockTime = time.Hour
// 	var totalBatchTime, maxBatchTime time.Duration
// 	var minBatchTime = time.Hour

// 	// Calculate block timing metrics
// 	for _, bt := range blockTimes {
// 		totalBlockTime += bt
// 		if bt > maxBlockTime {
// 			maxBlockTime = bt
// 		}
// 		if bt < minBlockTime {
// 			minBlockTime = bt
// 		}
// 	}

// 	// Calculate batch timing metrics
// 	for _, bt := range batchTimes {
// 		totalBatchTime += bt
// 		if bt > maxBatchTime {
// 			maxBatchTime = bt
// 		}
// 		if bt < minBatchTime {
// 			minBatchTime = bt
// 		}
// 	}

// 	avgBlockTime := totalBlockTime / time.Duration(len(blockTimes))
// 	avgBatchTime := totalBatchTime / time.Duration(len(batchTimes))
// 	totalTime := time.Since(startTime)

// 	// Log comprehensive metrics
// 	t.Logf("\nDetailed metrics for %s:", testName)
// 	t.Logf("Average block time: %v", avgBlockTime)
// 	t.Logf("Minimum block time: %v", minBlockTime)
// 	t.Logf("Maximum block time: %v", maxBlockTime)
// 	t.Logf("Average batch time: %v", avgBatchTime)
// 	t.Logf("Minimum batch time: %v", minBatchTime)
// 	t.Logf("Maximum batch time: %v", maxBatchTime)
// 	t.Logf("Total processing time: %v", totalTime)
// 	t.Logf("Transactions processed: %d", len(blockTimes)*txsPerBlock)
// 	t.Logf("Average TPS: %.2f", float64(len(blockTimes)*txsPerBlock)/totalTime.Seconds())
// 	t.Logf("Effective batch TPS: %.2f", float64(txsPerBlock)/avgBatchTime.Seconds())

// 	// Log shard-specific metrics
// 	t.Logf("\nShard metrics:")
// 	for shardID, metrics := range shardMetrics {
// 		t.Logf("Shard %d - Accesses: %d, Modifications: %d",
// 			shardID, metrics.accesses, metrics.modifies)
// 	}

// 	// Verify expectations
// 	require.Less(t, avgBlockTime, 2*expectedBlockTime,
// 		"Average block time exceeds twice the target block time")
// 	require.Less(t, totalTime, expectedMaxTime,
// 		"Total processing time exceeds maximum allowed time")
// }
