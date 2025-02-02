package network

// import (
// 	"bytes"
// 	"encoding/base64"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
// 	thrylos "github.com/thrylos-labs/thrylos"
// 	"github.com/thrylos-labs/thrylos/balance"
// 	"github.com/thrylos-labs/thrylos/chain"
// 	"github.com/thrylos-labs/thrylos/consensus/staking"
// 	"github.com/thrylos-labs/thrylos/consensus/validator"
// 	"github.com/thrylos-labs/thrylos/shared"
// 	"github.com/thrylos-labs/thrylos/state"

// 	"github.com/joho/godotenv"
// )

// //a central component that coordinates between different parts of the system.

// // Node defines a blockchain node with its properties and capabilities within the  It represents both
// // a ledger keeper and a participant in the blockchain's consensus mechanism. Each node maintains a copy of
// // the blockcFetchGasEstimatehain, a list of peers, a shard reference, and a pool of pending transactions to be included in future blocks.
// type Node struct {
// 	Address             string              // Network address of the node.
// 	Blockchain          *chain.Blockchain   // The blockchain maintained by this node.
// 	StateManager        *state.StateManager // Replace Shard field
// 	PendingTransactions []*thrylos.Transaction
// 	PublicKeyMap        map[string]mldsa44.PublicKey // Updated to store mldsa44 public keys
// 	chainID             string
// 	ResponsibleUTXOs    map[string]chain.UTXO // Tracks UTXOs for which the node is responsible
// 	// Database provides an abstraction over the underlying database technology used to persist
// 	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
// 	Database       shared.BlockchainDBInterface // Updated the type to interface
// 	GasEstimateURL string                       // New field to store the URL for gas estimation
// 	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
// 	// preventing race conditions and ensuring data integrity.
// 	Mu                   sync.RWMutex
// 	WebSocketConnections map[string]*WebSocketConnection
// 	WebSocketMutex       sync.RWMutex
// 	balanceUpdateQueue   *balance.BalanceUpdateQueue
// 	blockProducer        *chain.ModernBlockProducer
// 	StakingService       *staking.StakingService
// 	serverHost           string
// 	useSSL               bool
// 	//ModernProcessor      *processor.ModernProcessor
// 	BlockTrigger chan struct{}
// 	//DAGManager           *processor.DAGManager
// 	Peers       map[string]*PeerConnection
// 	PeerMu      sync.RWMutex
// 	MaxInbound  int
// 	MaxOutbound int
// 	txStatusMap sync.Map
// 	VoteCounter *validator.VoteCounter
// 	//ValidatorSelector  *validator.ValidatorSelector
// 	IsVoteCounter      bool   // Indicates if this node is the designated vote counter
// 	VoteCounterAddress string // Address of the designated vote counter
// 	BalanceManager     *balance.Manager
// }

// // GetActiveValidators returns a list of addresses for currently active validators
// func (node *Node) GetActiveValidators() []string {
// 	node.Mu.RLock()
// 	defer node.Mu.RUnlock()

// 	// Get all staking data from the staking service
// 	stakingStats := node.StakingService.GetPoolStats()
// 	validators := make([]string, 0)

// 	// Extract the minimum stake requirement
// 	minStake, ok := stakingStats["minimumStake"].(int64)
// 	if !ok {
// 		log.Printf("Warning: Could not get minimum stake requirement, using default")
// 		minStake = 40 // Default minimum stake in THRYLOS tokens
// 	}

// 	// Get all stakeholders
// 	stakeholders := node.GetStakeholders()

// 	// Filter for addresses that meet the minimum stake requirement
// 	for address, stake := range stakeholders {
// 		if stake >= minStake {
// 			validators = append(validators, address)
// 		}
// 	}

// 	return validators
// }

// // IsActiveValidator checks if a given address is an active validator
// func (node *Node) IsActiveValidator(address string) bool {
// 	node.Mu.RLock()
// 	defer node.Mu.RUnlock()

// 	// Get stake amount for the address
// 	stakeholders := node.GetStakeholders()
// 	stake, exists := stakeholders[address]
// 	if !exists {
// 		return false
// 	}

// 	// Get minimum stake requirement
// 	stakingStats := node.StakingService.GetPoolStats()
// 	minStake, ok := stakingStats["minimumStake"].(int64)
// 	if !ok {
// 		log.Printf("Warning: Could not get minimum stake requirement, using default")
// 		minStake = 40 // Default minimum stake in THRYLOS tokens
// 	}

// 	// Check if stake meets minimum requirement
// 	return stake >= minStake
// }

// // GetStakeholders returns a map of addresses to their staked amounts
// func (node *Node) GetStakeholders() map[string]int64 {
// 	node.Mu.RLock()
// 	defer node.Mu.RUnlock()

// 	stakeholders := make(map[string]int64)

// 	// Get all stakes from the staking service
// 	stats := node.StakingService.GetPoolStats()

// 	// Extract stakes from the pool stats
// 	if stakes, ok := stats["stakes"].(map[string]interface{}); ok {
// 		for address, stakeInfo := range stakes {
// 			if stake, ok := stakeInfo.(map[string]interface{}); ok {
// 				if amount, ok := stake["amount"].(int64); ok {
// 					stakeholders[address] = amount
// 				}
// 			}
// 		}
// 	}

// 	return stakeholders
// }

// // Hold the chain ID and then proviude a method to set it
// func (n *Node) SetChainID(chainID string) {
// 	n.chainID = chainID
// }

// func loadEnv() (map[string]string, error) {
// 	env := os.Getenv("ENV")
// 	var envPath string
// 	if env == "production" {
// 		envPath = "../../.env.prod" // The Cert is managed through the droplet
// 	} else {
// 		envPath = "../../.env.dev" // Managed through local host
// 	}
// 	envFile, err := godotenv.Read(envPath)

// 	return envFile, err
// }

// // NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// // blockchain instance for the node and optionally discovers peers if not running in a test environment.
// func NewNode(address string, knownPeers []string, dataDir string, stateManager *state.StateManager) *Node {
// 	// Default values for WebSocket configuration
// 	serverHost := address                            // Use the node's address as default server host
// 	useSSL := strings.HasPrefix(address, "https://") // Determine SSL based on address

// 	envFile, _ := loadEnv() // Dynamically load the correct environment configuration

// 	// Retrieve the AES key securely from an environment variable, with a fallback for tests
// 	aesKeyEncoded := envFile["AES_KEY_ENV_VAR"]

// 	log.Printf("AES Key from environment: %s", aesKeyEncoded)

// 	aesKey, err := base64.StdEncoding.DecodeString(aesKeyEncoded)
// 	if err != nil {
// 		log.Fatalf("Failed to decode AES key: %v", err)
// 	} else {
// 		log.Println("AES key decoded successfully")
// 	}

// 	// Retrieve the URL for gas estimation from an environment variable
// 	gasEstimateURL := envFile["GAS_ESTIMATE_URL"]
// 	if gasEstimateURL == "" {
// 		log.Fatal("Gas estimate URL is not set in environment variables. Please configure it before starting.")
// 	}

// 	// Assuming you have a way to get or set a default genesis account address
// 	genesisAccount := envFile["GENESIS_ACCOUNT"]
// 	if genesisAccount == "" {
// 		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
// 	}

// 	if err != nil {
// 		log.Fatalf("error initializing app: %v\n", err)
// 	}

// 	bc, db, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
// 		DataDir:           dataDir,
// 		AESKey:            aesKey,
// 		GenesisAccount:    genesisAccount,
// 		TestMode:          true,
// 		DisableBackground: false,
// 	})
// 	if err != nil {
// 		log.Fatalf("Failed to create new blockchain: %v", err)
// 	}

// 	// Initialize staking service with the blockchain
// 	stakingService := staking.NewStakingService(bc)

// 	node := &Node{
// 		Address:              address,
// 		Peers:                make(map[string]*PeerConnection),
// 		Blockchain:           bc,
// 		Database:             db,
// 		StateManager:         stateManager,
// 		PublicKeyMap:         make(map[string]mldsa44.PublicKey),
// 		ResponsibleUTXOs:     make(map[string]chain.UTXO),
// 		GasEstimateURL:       gasEstimateURL,
// 		WebSocketConnections: make(map[string]*WebSocketConnection),
// 		StakingService:       stakingService,
// 		serverHost:           serverHost,
// 		useSSL:               useSSL,
// 		BlockTrigger:         make(chan struct{}, 1),
// 		MaxInbound:           30,
// 		MaxOutbound:          20,
// 	}

// 	wsManager := NewWebSocketManager(node)
// 	node.BalanceManager = balance.NewManager(node, wsManager)

// 	isDesignatedCounter := false
// 	if len(bc.GetActiveValidators()) > 0 {
// 		// Make the first validator the designated counter
// 		isDesignatedCounter = (address == bc.GetActiveValidators()[0])
// 	}

// 	// Initialize VoteCounter with designation status
// 	node.VoteCounter = validator.NewVoteCounter(node, isDesignatedCounter)

// 	if isDesignatedCounter {
// 		log.Printf("Node %s designated as vote counter", address)
// 	}
// 	// Initialize ValidatorSelector with node
// 	//node.ValidatorSelector = validator.NewValidatorSelector(bc, node)

// 	//node.InitializeProcessors()

// 	// Add known peers as outbound connections
// 	// for _, peer := range knownPeers {
// 	// 	if err := AddPeer(peer, false); err != nil {
// 	// 		log.Printf("Failed to add known peer %s: %v", peer, err)
// 	// 	}
// 	// }

// 	// Initialize block producer after node is set up
// 	node.blockProducer = chain.NewBlockProducer(node, bc)
// 	node.blockProducer.Start()

// 	// Set the callback function
// 	//node.Blockchain.OnNewBlock = node.ProcessConfirmedTransactions

// 	// Initialize the balanceUpdateQueue
// 	//node.balanceUpdateQueue = node.newBalanceUpdateQueue(node)

// 	// Start the balance update worker goroutine
// 	//go node.balanceUpdateQueue.balanceUpdateWorker()

// 	//DiscoverPeers()

// 	//bc.OnTransactionProcessed = node.handleProcessedTransaction

// 	go node.startStakingTasks()

// 	return node
// }

// // Lifecycle methods (StartBackgroundTasks, Shutdown)

// func (node *Node) Shutdown() error {
// 	if node.blockProducer != nil {
// 		node.blockProducer.Stop()
// 	}
// 	// ... other cleanup ...
// 	return nil
// }

// func (node *Node) StartBackgroundTasks() {
// 	tickerDiscoverPeers := time.NewTicker(10 * time.Minute)
// 	go func() {
// 		for {
// 			select {
// 			case <-tickerDiscoverPeers.C:
// 				node.DiscoverPeers()
// 			}
// 		}
// 	}()

// 	// Add vote synchronization
// 	tickerVoteSync := time.NewTicker(30 * time.Second)
// 	go func() {
// 		for {
// 			select {
// 			case <-tickerVoteSync.C:
// 				node.syncVotes()
// 			}
// 		}
// 	}()
// }

// func (node *Node) startStakingTasks() {
// 	ticker := time.NewTicker(24 * time.Hour)
// 	for {
// 		select {
// 		case <-ticker.C:
// 			if err := node.StakingService.DistributeRewards(); err != nil {
// 				log.Printf("Error distributing staking rewards: %v", err)
// 			}
// 		}
// 	}
// }

// // These methods are correct as they simply proxy the calls
// func (node *Node) GetStakingStats() map[string]interface{} {
// 	return node.StakingService.GetPoolStats()
// }

// func (node *Node) CreateStake(userAddress string, amount int64) (*staking.Stake, error) {
// 	return node.StakingService.CreateStake(userAddress, amount)
// }

// func (node *Node) ValidateAndVoteForBlock(block *chain.Block) error {
// 	// Perform block validation
// 	if err := node.Blockchain.VerifySignedBlock(block); err != nil {
// 		return fmt.Errorf("block validation failed: %v", err)
// 	}

// 	// Create vote with validation result
// 	vote := validator.Vote{
// 		ValidatorID:    string(block.ValidatorAddress),
// 		BlockNumber:    block.Index,
// 		BlockHash:      block.Hash,
// 		ValidationPass: true,
// 		Timestamp:      time.Now(),
// 		VoterNode:      node.Address,
// 	}

// 	// Send vote to designated counter node
// 	if err := node.sendVoteToCounter(vote); err != nil {
// 		return fmt.Errorf("failed to send vote to counter: %v", err)
// 	}

// 	return nil
// }

// func (node *Node) sendVoteToCounter(vote validator.Vote) error {
// 	if node.IsVoteCounter {
// 		// If this is the counter node, process locally
// 		return node.VoteCounter.AddVote(vote)
// 	}

// 	// Send to designated counter node
// 	voteData, err := json.Marshal(vote)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal vote: %v", err)
// 	}

// 	url := fmt.Sprintf("%s/vote", node.VoteCounterAddress)
// 	resp, err := http.Post(url, "application/json", bytes.NewBuffer(voteData))
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return fmt.Errorf("vote counter returned non-OK status: %d", resp.StatusCode)
// 	}

// 	return nil
// }

// func (n *Node) ConfirmBlock(blockNumber int32) {
// 	if !n.IsVoteCounter {
// 		return
// 	}

// 	// Broadcast confirmation to all nodes
// 	confirmation := struct {
// 		BlockNumber int32
// 		Confirmed   bool
// 	}{
// 		BlockNumber: blockNumber,
// 		Confirmed:   true,
// 	}

// 	n.BroadcastBlockConfirmation(confirmation)
// }

// func (node *Node) BroadcastBlockConfirmation(confirmation struct {
// 	BlockNumber int32
// 	Confirmed   bool
// }) {
// 	// Convert confirmation to JSON
// 	confirmationData, err := json.Marshal(confirmation)
// 	if err != nil {
// 		log.Printf("Failed to marshal block confirmation: %v", err)
// 		return
// 	}

// 	// Broadcast to all peers
// 	for _, peer := range node.Peers {
// 		url := fmt.Sprintf("%s/block-confirmation", peer.Address)
// 		resp, err := http.Post(url, "application/json", bytes.NewBuffer(confirmationData))
// 		if err != nil {
// 			log.Printf("Failed to send confirmation to peer %s: %v", peer.Address, err)
// 			continue
// 		}
// 		resp.Body.Close()
// 	}

// 	log.Printf("Block %d confirmation broadcast to all peers", confirmation.BlockNumber)
// }

// // This method should be aligned with how we're handling stake determinations
// func (node *Node) UnstakeTokens(userAddress string, isDelegator bool, amount int64) error {
// 	// We should determine if it's a delegator by checking validator status
// 	isValidator := node.StakingService.IsValidator(userAddress)
// 	isDelegator = !isValidator

// 	txType := "unstake"
// 	if isDelegator {
// 		txType = "undelegate"
// 	}

// 	txID := fmt.Sprintf("%s-%s-%d", txType, userAddress, time.Now().UnixNano())
// 	timestamp := time.Now().Unix()

// 	unstakingTx := &thrylos.Transaction{
// 		Id:        txID,
// 		Sender:    "staking_pool",
// 		Timestamp: timestamp,
// 		Outputs: []*thrylos.UTXO{{
// 			OwnerAddress:  userAddress,
// 			Amount:        amount,
// 			Index:         0,
// 			TransactionId: "",
// 		}},
// 	}

// 	if err := node.Blockchain.AddPendingTransaction(unstakingTx); err != nil {
// 		return fmt.Errorf("failed to create unstaking transaction: %v", err)
// 	}

// 	return node.StakingService.unstakeTokensInternal(userAddress, isDelegator, amount, timestamp)
// }

// // These delegation-specific methods are correct
// func (node *Node) DelegateToPool(delegator string, amount int64) (*staking.Stake, error) {
// 	return node.StakingService.CreateStake(delegator, amount)
// }

// func (node *Node) UndelegateFromPool(delegator string, amount int64) error {
// 	return node.UnstakeTokens(delegator, true, amount)
// }

// func (node *Node) GetValidatorVoteStatus(validatorID string) int {
// 	return node.VoteCounter.GetVoteCount(validatorID)
// }

// func (node *Node) GetBlockchainStats() *chain.BlockchainStats {
// 	blockCount, txCount := node.Blockchain.StatsCollector.GetBlockStats()
// 	return &chain.BlockchainStats{
// 		NumberOfBlocks:       blockCount,
// 		NumberOfTransactions: txCount,
// 		TotalStake:           node.Blockchain.StatsCollector.GetTotalStake(),
// 		NumberOfPeers:        len(node.Peers),
// 	}
// }

// func (node *Node) BroadcastVote(validatorID string, blockNumber int32) error {
// 	vote := validator.Vote{
// 		ValidatorID: validatorID,
// 		BlockNumber: blockNumber,
// 		Timestamp:   time.Now(),
// 		VoterNode:   node.Address,
// 	}

// 	// If this node is not the vote counter, send to the designated counter
// 	if !node.IsVoteCounter {
// 		// Send vote to specific vote counter node
// 		counterPeer, exists := node.Peers[node.VoteCounterAddress]
// 		if !exists {
// 			return fmt.Errorf("vote counter node not found in peers")
// 		}
// 		return counterPeer.SendVote(vote)
// 	}

// 	// If this is the vote counter node, process the vote
// 	node.VoteCounter.AddVote(vote)
// 	return nil
// }

// // Validate block and send vote
// func (node *Node) ValidateAndVoteOnBlock(block *chain.Block) error {
// 	// Validate the block
// 	if err := node.Blockchain.VerifySignedBlock(block); err != nil {
// 		return fmt.Errorf("block validation failed: %v", err)
// 	}

// 	// If validation successful, send vote to counter node
// 	return node.BroadcastVote(block.Validator, block.Index)
// }

// func (node *Node) syncVotes() {
// 	for _, peer := range node.Peers {
// 		resp, err := http.Get(fmt.Sprintf("%s/votes", peer.Address))
// 		if err != nil {
// 			log.Printf("Failed to sync votes with peer %s: %v", peer.Address, err)
// 			continue
// 		}
// 		defer resp.Body.Close()

// 		var votes []validator.Vote
// 		if err := json.NewDecoder(resp.Body).Decode(&votes); err != nil {
// 			log.Printf("Failed to decode votes from peer %s: %v", peer.Address, err)
// 			continue
// 		}

// 		for _, vote := range votes {
// 			node.VoteCounter.AddVote(vote)
// 		}
// 	}
// }
