package core

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/golang-jwt/jwt/v4"
	"github.com/supabase-community/supabase-go"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"

	"github.com/joho/godotenv"
)

// Vote represents a vote cast by a validator for a specific block. It includes the block hash being voted for,
// the validator's address, and the stake the validator had at the time of voting. This is used in consensus mechanisms
// that involve staking and voting for block validity.
type Vote struct {
	BlockHash []byte // Hash of the block that is being voted for.
	Validator string // Address of the validator casting the vote.
	Stake     int64  // Stake amount of the validator at the time of voting.
}

// Node defines a blockchain node with its properties and capabilities within the network. It represents both
// a ledger keeper and a participant in the blockchain's consensus mechanism. Each node maintains a copy of
// the blockcFetchGasEstimatehain, a list of peers, a shard reference, and a pool of pending transactions to be included in future blocks.
type Node struct {
	Address             string      // Network address of the node.
	Peers               []string    // Addresses of peer nodes for communication within the network.
	Blockchain          *Blockchain // The blockchain maintained by this node.
	Votes               []Vote      // Collection of votes for blocks from validators.
	Shard               *Shard      // Reference to the shard this node is part of, if sharding is implemented.
	PendingTransactions []*thrylos.Transaction
	PublicKeyMap        map[string]ed25519.PublicKey // Updated to store ed25519 public keys
	chainID             string
	ResponsibleUTXOs    map[string]shared.UTXO // Tracks UTXOs for which the node is responsible
	// Database provides an abstraction over the underlying database technology used to persist
	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
	Database       shared.BlockchainDBInterface // Updated the type to interface
	GasEstimateURL string                       // New field to store the URL for gas estimation
	SupabaseClient *supabase.Client
	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
	// preventing race conditions and ensuring data integrity.
	Mu                   sync.RWMutex
	WebSocketConnections map[string]*WebSocketConnection
	WebSocketMutex       sync.RWMutex
	balanceUpdateQueue   *BalanceUpdateQueue
}

// Hold the chain ID and then proviude a method to set it
func (n *Node) SetChainID(chainID string) {
	n.chainID = chainID
}

func loadEnv() (map[string]string, error) {
	env := os.Getenv("ENV")
	var envPath string
	if env == "production" {
		envPath = "../../.env.prod" // The Cert is managed through the droplet
	} else {
		envPath = "../../.env.dev" // Managed through local host
	}
	envFile, err := godotenv.Read(envPath)

	return envFile, err
}

// NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// blockchain instance for the node and optionally discovers peers if not running in a test environment.
func NewNode(address string, knownPeers []string, dataDir string, shard *Shard) *Node {
	envFile, _ := loadEnv() // Dynamically load the correct environment configuration

	// Retrieve the AES key securely from an environment variable, with a fallback for tests
	aesKeyEncoded := envFile["AES_KEY_ENV_VAR"]

	log.Printf("AES Key from environment: %s", aesKeyEncoded) // Debug output to see what is retrieved

	aesKey, err := base64.StdEncoding.DecodeString(aesKeyEncoded)
	if err != nil {
		log.Fatalf("Failed to decode AES key: %v", err)
	} else {
		log.Println("AES key decoded successfully")
	}

	// Retrieve the URL for gas estimation from an environment variable
	gasEstimateURL := envFile["GAS_ESTIMATE_URL"]
	if gasEstimateURL == "" {
		log.Fatal("Gas estimate URL is not set in environment variables. Please configure it before starting.")
	}

	// Assuming you have a way to get or set a default genesis account address
	genesisAccount := envFile["GENESIS_ACCOUNT"]
	if genesisAccount == "" {
		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
	}

	supabaseURL := envFile["SUPABASE_URL"]
	supabasePublicKey := envFile["SUPABASE_PUBLIC_KEY"]
	supabaseClient, err := supabase.NewClient(supabaseURL, supabasePublicKey, nil)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	bc, db, err := NewBlockchain(dataDir, aesKey, genesisAccount, true, supabaseClient)
	if err != nil {
		log.Fatalf("Failed to create new blockchain: %v", err)
	}

	node := &Node{
		Address:              address,
		Peers:                knownPeers,
		Blockchain:           bc,
		Database:             db, // Set the Database field
		Shard:                shard,
		SupabaseClient:       supabaseClient,
		PublicKeyMap:         make(map[string]ed25519.PublicKey), // Initialize the map
		ResponsibleUTXOs:     make(map[string]shared.UTXO),
		GasEstimateURL:       gasEstimateURL, // Set the URL in the node struct
		WebSocketConnections: make(map[string]*WebSocketConnection),
	}

	// Set the callback function
	node.Blockchain.OnNewBlock = node.ProcessConfirmedTransactions

	// Initialize the balanceUpdateQueue
	node.balanceUpdateQueue = newBalanceUpdateQueue(node)

	// Start the balance update worker goroutine
	go node.balanceUpdateQueue.balanceUpdateWorker()

	if shard != nil {
		shard.AssignNode(node)
	}

	node.DiscoverPeers() // Skip this during tests

	bc.OnTransactionProcessed = node.handleProcessedTransaction

	return node
}

func (n *Node) handleProcessedTransaction(tx *thrylos.Transaction) {
	addresses := make(map[string]bool)
	addresses[tx.Sender] = true
	for _, output := range tx.Outputs {
		addresses[output.OwnerAddress] = true
	}

	for address := range addresses {
		if err := n.SendBalanceUpdate(address); err != nil {
			log.Printf("Failed to send balance update for %s: %v", address, err)
		}
	}
}

// Since these methods pertain to the behavior of a node
// in your network and involve voting for blocks and counting votes, they should be grouped with other node-related functionalities.

// VoteForBlock allows a node to cast a vote for a specific block. It is part of the consensus mechanism,
// where validators with a stake in the blockchain vote to determine the validity of blocks.
func (node *Node) VoteForBlock(block *Block) {
	stake, exists := node.Blockchain.Stakeholders[node.Address]
	if !exists || stake < minStakeRequirement {
		return // This node doesn't have enough stake to vote
	}

	vote := Vote{BlockHash: block.Hash, Validator: node.Address, Stake: stake}
	voteData, err := json.Marshal(vote)
	if err != nil {
		fmt.Println("Failed to serialize vote:", err)
		return
	}

	for _, peer := range node.Peers {
		http.Post(peer+"/vote", "application/json", bytes.NewBuffer(voteData))
	}
}

// HasBlock checks whether a block with the specified hash exists in the node's blockchain.
func (n *Node) HasBlock(blockHash []byte) bool {
	log.Printf("Searching for block with hash: %s", hex.EncodeToString(blockHash))
	for _, block := range n.Blockchain.Blocks {
		if bytes.Equal(block.Hash, blockHash) {
			log.Printf("Block found: %s", hex.EncodeToString(block.Hash))
			return true
		}
	}
	log.Println("Block not found")
	return false
}

// HasTransaction checks whether a transaction with the specified ID exists in the node's pool of pending transactions.
func (node *Node) HasTransaction(txID string) bool {
	for _, tx := range node.PendingTransactions {
		if tx.GetId() == txID {
			return true
		}
	}
	return false
}

func (node *Node) CollectInputsForTransaction(amount int64, senderAddress string) (inputs []shared.UTXO, change int64, err error) {
	var collectedAmount int64
	var collectedInputs []shared.UTXO

	utxos, err := node.Blockchain.GetUTXOsForAddress(senderAddress)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range utxos {
		if collectedAmount >= amount {
			break
		}
		collectedAmount += utxo.Amount
		collectedInputs = append(collectedInputs, utxo)
	}

	if collectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds available")
	}

	change = collectedAmount - amount
	return collectedInputs, change, nil
}

// CalculateGas computes the gas fee based on the size of the transaction data.
const (
	BaseGasFee = 1000  // Base fee in microTHRYLOS (0.001 THRYLOS)
	MaxGasFee  = 10000 // Maximum gas fee in microTHRYLOS (0.01 THRYLOS)
)

func CalculateGas(dataSize int, balance int64) int {
	// Start with the base fee
	gasFee := BaseGasFee

	// Add additional fee based on data size
	// This adds 100 microTHRYLOS (0.0001 THRYLOS) for every 1000 bytes
	additionalFee := (dataSize / 1000) * 100
	gasFee += additionalFee

	if gasFee > MaxGasFee {
		gasFee = MaxGasFee
	}

	return gasFee // This will be between 1000 and 10000, representing 0.001 to 0.01 THRYLOS
}

func (node *Node) RetrievePublicKey(address string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	pubKey, err := node.Blockchain.Database.RetrievePublicKeyFromAddress(address)
	if err != nil {
		log.Printf("Public key not found for address: %s, error: %v", address, err)
		return nil, fmt.Errorf("public key not found for address: %s, error: %v", address, err)
	}
	log.Printf("Public key retrieved for address: %s", address)
	return pubKey, nil
}

func (node *Node) StorePublicKey(address string, publicKey ed25519.PublicKey) {
	node.PublicKeyMap[address] = publicKey
}

// VerifyAndProcessTransaction verifies the transaction's signature using Ed25519 and processes it if valid.
func (node *Node) VerifyAndProcessTransaction(tx *thrylos.Transaction) error {
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction has no inputs")
	}

	// Retrieve the sender's address from the transaction directly
	senderAddress := tx.Sender
	if senderAddress == "" {
		log.Printf("Transaction with empty sender address: %+v", tx)
		return fmt.Errorf("sender address is empty")
	}

	// Example format validation for the sender's address (adapt regex to your needs)
	if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(senderAddress) {
		log.Printf("Invalid sender address format: %s", senderAddress)
		return fmt.Errorf("invalid sender address format: %s", senderAddress)
	}

	log.Printf("VerifyAndProcessTransaction: Verifying transaction for sender address: %s", senderAddress)
	// Retrieve the Ed25519 public key using the sender's address
	senderEd25519PublicKey, err := node.Blockchain.RetrievePublicKey(senderAddress)
	if err != nil {
		log.Printf("VerifyAndProcessTransaction: Failed to retrieve or validate Ed25519 public key for address %s: %v", senderAddress, err)
		return fmt.Errorf("failed to retrieve or validate Ed25519 public key: %v", err)
	}

	// Verify the transaction signature with the retrieved public keys
	if err := shared.VerifyTransactionSignature(tx, senderEd25519PublicKey); err != nil {
		return fmt.Errorf("transaction signature verification failed: %v", err)
	}

	// Process the transaction if all checks pass
	return nil
}

func sendResponse(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// Assuming ConvertThrylosToSharedTransaction is a function you will create to convert between these transaction types
// ConvertThrylosToProtoTransaction converts your internal transaction representation to the protobuf representation
func ConvertThrylosToProtoTransaction(thrylosTx *thrylos.Transaction) *thrylos.Transaction {
	// Since thrylosTx is already the type we want, assuming it's generated from protobuf, we don't need to convert field by field
	// Just return the transaction as it matches the protobuf definition
	return thrylosTx
}

func ThrylosToShared(tx *thrylos.Transaction) *shared.Transaction {
	if tx == nil {
		return nil
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(tx.GetSignature())

	return &shared.Transaction{
		ID:            tx.GetId(),
		Timestamp:     tx.GetTimestamp(),
		Inputs:        ConvertProtoInputs(tx.GetInputs()),
		Outputs:       ConvertProtoOutputs(tx.GetOutputs()),
		Signature:     signatureBase64, // Now properly encoded as a Base64 string
		PreviousTxIds: tx.GetPreviousTxIds(),
	}
}

func ConvertProtoInputs(inputs []*thrylos.UTXO) []shared.UTXO {
	sharedInputs := make([]shared.UTXO, len(inputs))
	for i, input := range inputs {
		if input != nil {
			sharedInputs[i] = shared.UTXO{
				TransactionID: input.GetTransactionId(),
				Index:         int(input.GetIndex()), // Corrected type conversion
				OwnerAddress:  input.GetOwnerAddress(),
				Amount:        int64(input.GetAmount()), // Corrected type conversion
			}
		}
	}
	return sharedInputs
}

func ConvertProtoOutputs(outputs []*thrylos.UTXO) []shared.UTXO {
	sharedOutputs := make([]shared.UTXO, len(outputs))
	for i, output := range outputs {
		if output != nil {
			sharedOutputs[i] = shared.UTXO{
				TransactionID: output.GetTransactionId(),
				Index:         int(output.GetIndex()), // Corrected type conversion
				OwnerAddress:  output.GetOwnerAddress(),
				Amount:        int64(output.GetAmount()), // Corrected type conversion
			}
		}
	}
	return sharedOutputs
}

// fetch all transactions for a given block
func (node *Node) ListTransactionsForBlockHandler(w http.ResponseWriter, r *http.Request) {
	blockID := r.URL.Query().Get("id")
	if blockID == "" {
		http.Error(w, "Block ID is required", http.StatusBadRequest)
		return
	}
	block, err := node.Blockchain.GetBlockByID(blockID)
	if err != nil {
		http.Error(w, "Block not found: "+err.Error(), http.StatusNotFound)
		return
	}
	// Serialize the transactions of the block for response
	transactionsJSON, err := json.Marshal(block.Transactions)
	if err != nil {
		http.Error(w, "Failed to serialize transactions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(transactionsJSON)
}

// Allows users to register their public keys with Thrylos, enssential for transactions where public keys are needed
func (node *Node) RegisterPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Use node.Blockchain to access the RegisterPublicKey method
	if err := node.Blockchain.RegisterPublicKey(req.PublicKey); err != nil {
		http.Error(w, "Failed to register public key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Public key registered successfully"))
}

func (node *Node) GetPendingTransactions() []*thrylos.Transaction {
	return node.PendingTransactions
}

func (node *Node) PendingTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	pendingTransactions := node.GetPendingTransactions()
	txData, err := json.Marshal(pendingTransactions)
	if err != nil {
		http.Error(w, "Failed to serialize pending transactions", http.StatusInternalServerError)
		return
	}
	sendResponse(w, txData)
}

// GetBlockHandler retrieves a specific block by ID.
func (node *Node) GetBlockHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		blockID := r.URL.Query().Get("id")
		if blockID == "" {
			http.Error(w, "Block ID is required", http.StatusBadRequest)
			return
		}

		block, err := node.Blockchain.GetBlockByID(blockID)
		if err != nil {
			http.Error(w, "Block not found", http.StatusNotFound)
			return
		}

		// Check if the block transactions are not null
		if block.Transactions == nil {
			log.Printf("No transactions found in block %s", blockID)
		}

		blockJSON, err := json.Marshal(block)
		if err != nil {
			log.Printf("Error serializing block: %v", err)
			http.Error(w, "Failed to serialize block", http.StatusInternalServerError)
			return
		}

		log.Printf("Sending block data: %s", string(blockJSON))
		w.Header().Set("Content-Type", "application/json")
		w.Write(blockJSON)
	}
}

func (node *Node) GetTransactionHandler(w http.ResponseWriter, r *http.Request) {
	txID := r.URL.Query().Get("id")
	if txID == "" {
		http.Error(w, "Transaction ID is required", http.StatusBadRequest)
		return
	}
	tx, err := node.Blockchain.GetTransactionByID(txID)
	if err != nil {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}
	txJSON, err := json.Marshal(tx)
	if err != nil {
		http.Error(w, "Failed to serialize transaction", http.StatusInternalServerError)
		return
	}

	sendResponse(w, txJSON)
}

func (node *Node) NetworkHealthHandler(w http.ResponseWriter, r *http.Request) {
	healthInfo := struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{
		Status:  "OK",
		Message: "Node is active and connected to peers",
	}
	// You might want to include actual checks here to validate connectivity, block height synchronization, etc.
	if len(node.Peers) == 0 {
		healthInfo.Status = "WARNING"
		healthInfo.Message = "Node is not connected to any peers"
	}
}

const NanoThrylosPerThrylos = 1e7

func formatBalance(balanceNano int64) string {
	balanceThrylos := float64(balanceNano) / NanoThrylosPerThrylos
	return fmt.Sprintf("%d nanoTHRYLOS (%.7f THRYLOS)", balanceNano, balanceThrylos)
}

func ThrylosToNanoNode(thrylos float64) int64 {
	return int64(thrylos * NanoThrylosPerThrylos)
}

func (node *Node) GetBalance(address string) (int64, error) {
	utxos, err := node.Blockchain.Database.GetUTXOsForAddress(address)
	if err != nil {
		log.Printf("Error fetching UTXOs for address %s: %v", address, err)
		return 0, err
	}

	balance := int64(0)
	for i, utxo := range utxos {
		if !utxo.IsSpent {
			balance += utxo.Amount
			log.Printf("UTXO %d: Amount = %d, TransactionID = %s", i, utxo.Amount, utxo.TransactionID)
		}
	}

	log.Printf("Final balance for %s: %s", address, formatBalance(balance))
	return balance, nil
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow requests from specific origins
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{"http://localhost:3000", "https://node.thrylos.org"}

		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				return true
			}
		}
		return false
	},
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

type WebSocketConnection struct {
	ws   *websocket.Conn
	send chan []byte
}

// Event only web socket updates
func (node *Node) WebSocketBalanceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received WebSocket connection request for balance updates")
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}

	address := r.URL.Query().Get("address")
	if address == "" {
		log.Println("Blockchain address is required")
		ws.WriteMessage(websocket.TextMessage, []byte("Blockchain address is required"))
		ws.Close()
		return
	}

	// Validate the address exists by attempting to retrieve its public key
	_, err = node.Database.RetrievePublicKeyFromAddress(address)
	if err != nil {
		log.Printf("Invalid address %s: %v", address, err)
		ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Invalid or unregistered address: %v", err)))
		ws.Close()
		return
	}

	log.Printf("WebSocket connection established for address: %s", address)

	conn := &WebSocketConnection{ws: ws, send: make(chan []byte, 256)}

	node.WebSocketMutex.Lock()
	node.WebSocketConnections[address] = conn
	node.WebSocketMutex.Unlock()

	// Send initial balance update once
	if err := node.SendBalanceUpdate(address); err != nil {
		log.Printf("Error sending initial balance update for address %s: %v", address, err)
	}

	go node.writePump(conn, address)
	go node.readPump(conn, address)
}

func (node *Node) HandleBlockchainEvent(address string) {
	// Check if we have a WebSocket connection for this address
	node.WebSocketMutex.RLock()
	_, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if exists {
		// Send balance update to the WebSocket
		if err := node.SendBalanceUpdate(address); err != nil {
			log.Printf("Error sending balance update for address %s: %v", address, err)
		} else {
			log.Printf("Balance update sent for address %s", address)
		}
	}
}

func (node *Node) writePump(conn *WebSocketConnection, address string) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		conn.ws.Close()
	}()

	for {
		select {
		case message, ok := <-conn.send:
			conn.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				log.Printf("WebSocket send channel closed for address: %s", address)
				conn.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := conn.ws.NextWriter(websocket.TextMessage)
			if err != nil {
				log.Printf("Error getting next writer for address %s: %v", address, err)
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				log.Printf("Error closing writer for address %s: %v", address, err)
				return
			}
			log.Printf("Successfully sent message to address %s: %s", address, string(message))

		case <-ticker.C:
			conn.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Error sending ping message for address %s: %v", address, err)
				return
			}
			log.Printf("Sent ping message to address: %s", address)
		}
	}
}

func (node *Node) readPump(conn *WebSocketConnection, address string) {
	defer func() {
		node.WebSocketMutex.Lock()
		delete(node.WebSocketConnections, address)
		node.WebSocketMutex.Unlock()
		conn.ws.Close()
		log.Printf("WebSocket connection closed for address: %s", address)
	}()

	conn.ws.SetReadLimit(maxMessageSize)
	conn.ws.SetReadDeadline(time.Now().Add(pongWait))
	conn.ws.SetPongHandler(func(string) error {
		conn.ws.SetReadDeadline(time.Now().Add(pongWait))
		log.Printf("Received pong from address: %s", address)
		return nil
	})

	for {
		_, _, err := conn.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error for address %s: %v", address, err)
			}
			break
		}
		log.Printf("Received message from address: %s", address)
	}
}

const NANO_THRYLOS_PER_THRYLOS = 1e7

type BalanceUpdateRequest struct {
	Address string
	Retries int
}

type BalanceUpdateQueue struct {
	queue chan BalanceUpdateRequest
	node  *Node
}

func newBalanceUpdateQueue(node *Node) *BalanceUpdateQueue {
	return &BalanceUpdateQueue{
		queue: make(chan BalanceUpdateRequest, 1000),
		node:  node,
	}
}

type PendingBalanceUpdate struct {
	Address   string
	Balance   int64
	Timestamp time.Time
}

var pendingBalanceUpdates = make(map[string][]PendingBalanceUpdate)
var pendingBalanceUpdatesMutex sync.RWMutex

func (node *Node) AddPendingBalanceUpdate(address string, balance int64) {
	pendingBalanceUpdatesMutex.Lock()
	defer pendingBalanceUpdatesMutex.Unlock()
	pendingBalanceUpdates[address] = append(pendingBalanceUpdates[address], PendingBalanceUpdate{
		Address:   address,
		Balance:   balance,
		Timestamp: time.Now(),
	})
	log.Printf("Added pending balance update for address %s: %d nanoTHRYLOS", address, balance)
}

// Sends updates through the websocket

func (node *Node) SendBalanceUpdate(address string) error {
	balanceInNano, err := node.GetBalance(address) // This returns nanoTHRYLOS
	if err != nil {
		return fmt.Errorf("failed to get balance for %s: %v", address, err)
	}

	// Convert to THRYLOS
	balanceInThrylos := float64(balanceInNano) / float64(NANO_THRYLOS_PER_THRYLOS)

	// Create update message
	update := struct {
		Address        string  `json:"blockchainAddress"`
		Balance        int64   `json:"balance"`        // In THRYLOS
		BalanceThrylos float64 `json:"balanceThrylos"` // In THRYLOS
	}{
		Address:        address,
		Balance:        balanceInNano,    // Keep original nanoTHRYLOS value
		BalanceThrylos: balanceInThrylos, // Send converted THRYLOS value
	}

	jsonUpdate, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal balance update: %v", err)
	}

	node.WebSocketMutex.RLock()
	conn, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if !exists {
		return fmt.Errorf("no WebSocket connection found for address: %s", address)
	}

	select {
	case conn.send <- jsonUpdate:
		log.Printf("Balance update sent for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
			address, balanceInNano, balanceInThrylos)
	default:
		return fmt.Errorf("WebSocket send buffer full for address: %s", address)
	}

	return nil
}

func (node *Node) handleBalanceUpdate(address string) {
	if err := node.SendBalanceUpdate(address); err != nil {
		log.Printf("Failed to send balance update for %s: %v", address, err)
	} else {
		balance, _ := node.GetBalance(address)
		log.Printf("Successfully sent balance update for %s. Current balance: %d nanoTHRYLOS",
			address, balance)
	}
}

func (node *Node) GetPendingBalanceUpdates(address string) []PendingBalanceUpdate {
	pendingBalanceUpdatesMutex.RLock()
	defer pendingBalanceUpdatesMutex.RUnlock()
	return pendingBalanceUpdates[address]
}

func (node *Node) RemovePendingBalanceUpdate(address string, update PendingBalanceUpdate) {
	pendingBalanceUpdatesMutex.Lock()
	defer pendingBalanceUpdatesMutex.Unlock()
	updates := pendingBalanceUpdates[address]
	for i, u := range updates {
		if u.Timestamp == update.Timestamp {
			pendingBalanceUpdates[address] = append(updates[:i], updates[i+1:]...)
			break
		}
	}
}

func (node *Node) ProcessPendingBalanceUpdates(address string) {
	pendingBalanceUpdatesMutex.Lock()
	pendingUpdates, exists := pendingBalanceUpdates[address]
	if exists {
		delete(pendingBalanceUpdates, address)
	}
	pendingBalanceUpdatesMutex.Unlock()

	if exists {
		log.Printf("Processing %d pending balance updates for address %s", len(pendingUpdates), address)
		for _, update := range pendingUpdates {
			if err := node.SendBalanceUpdate(address); err != nil {
				log.Printf("Error processing pending balance update for address %s: %v", address, err)
			} else {
				log.Printf("Processed pending balance update for address %s: %d nanoTHRYLOS", address, update.Balance)
			}
		}
	}
}

func (q *BalanceUpdateQueue) balanceUpdateWorker() {
	for req := range q.queue {
		success := false
		for attempt := 0; attempt < req.Retries && !success; attempt++ {
			if err := q.node.SendBalanceUpdate(req.Address); err == nil {
				success = true
			} else {
				log.Printf("Failed to update balance for %s, attempt %d: %v", req.Address, attempt+1, err)
				time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second)
			}
		}
		if !success {
			log.Printf("Failed to update balance for %s after %d attempts", req.Address, req.Retries)
		}
	}
}

// The faucet handler can utilize this genesis account without needing to specify which account to use:
// This endpoint will transfer a predefined amount of funds from a foundational account to a specified user's account.

func (node *Node) FaucetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		address := r.URL.Query().Get("address")
		amountStr := r.URL.Query().Get("amount")
		if address == "" {
			http.Error(w, `{"error":"Address parameter is missing"}`, http.StatusBadRequest)
			return
		}

		amount, err := strconv.ParseInt(amountStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"Invalid amount"}`, http.StatusBadRequest)
			return
		}

		err = node.Blockchain.TransferFunds("", address, amount) // Using the genesis account by default
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Failed to transfer funds: %v"}`, err), http.StatusInternalServerError)
			return
		}

		response := fmt.Sprintf(`{"message":"Transferred %d to %s successfully"}`, amount, address)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(response))
	}
}

type BlockchainStats struct {
	NumberOfBlocks       int   `json:"number_of_blocks"`
	NumberOfTransactions int   `json:"number_of_transactions"`
	TotalStake           int64 `json:"total_stake"`
	NumberOfPeers        int   `json:"number_of_peers"`
}

func (node *Node) GetBlockchainStats() BlockchainStats {
	var stats BlockchainStats
	stats.NumberOfBlocks = len(node.Blockchain.Blocks)
	stats.NumberOfTransactions = 0 // You'll need to iterate through blocks to count transactions
	for _, block := range node.Blockchain.Blocks {
		stats.NumberOfTransactions += len(block.Transactions)
	}
	stats.TotalStake = node.Blockchain.TotalStake()
	stats.NumberOfPeers = len(node.Peers)
	return stats
}

// TotalStake calculates the total amount of stake from all stakeholders in the blockchain. This is used
// in consensus mechanisms that involve staking.
func (bc *Blockchain) TotalStake() int64 {
	var total int64
	for _, stake := range bc.Stakeholders {
		total += stake
	}
	return total
}

// CountVotes tallies the votes for blocks from validators and updates the blockchain accordingly. It plays
// a crucial role in consensus mechanisms where blocks are accepted based on validator votes.
func (node *Node) CountVotes() {
	majorityStake := node.Blockchain.TotalStake()/2 + 1
	voteStakes := make(map[string]int64)

	for _, vote := range node.Votes {
		// Convert []byte to string for map key
		hashStr := hex.EncodeToString(vote.BlockHash)
		voteStakes[hashStr] += vote.Stake
		if voteStakes[hashStr] >= majorityStake {
			// This block has a majority stake vote
			// Find the block with this hash
			var majorityBlock *Block
			for _, block := range node.Blockchain.Blocks {
				if bytes.Equal(block.Hash, vote.BlockHash) {
					majorityBlock = block
					break
				}
			}

			if majorityBlock != nil {
				// Add it to the blockchain and broadcast it
				// node.Blockchain.AddBlock(majorityBlock)
				node.BroadcastBlock(majorityBlock)
				node.Votes = []Vote{} // Clear votes
				break
			} else {
				log.Printf("Majority block with hash %x not found", vote.BlockHash)
			}
		}
	}
}

// SecureRandomInt generates a cryptographically secure random integer within the range [0, max).
// It uses the crypto/rand package to ensure the randomness is suitable for security-sensitive operations.
// This function can be used in various blockchain contexts where randomness is required, such as
// selecting a validator randomly in a Proof of Stake (PoS) consensus mechanism or generating nonces.

func SecureRandomInt(max int64) (int64, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int64(nBig.Int64()), nil
}

const minStakeRequirement = 1000 // This represents the minimum amount of stake required to become a validator.

func (bc *Blockchain) SelectValidator() string {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	if len(bc.ActiveValidators) == 0 {
		fmt.Println("No active validators available.")
		return ""
	}

	var totalStake int64
	validatorStakes := make(map[string]int64)

	for _, validator := range bc.ActiveValidators {
		stake := bc.Stakeholders[validator]
		totalStake += stake
		validatorStakes[validator] = stake
	}

	if totalStake == 0 {
		fmt.Println("No stake available among active validators.")
		return ""
	}

	randStake, err := SecureRandomInt(totalStake)
	if err != nil {
		fmt.Println("Failed to generate secure random number:", err)
		return ""
	}

	for validator, stake := range validatorStakes {
		randStake -= stake
		if randStake < 0 {
			return validator
		}
	}

	return ""
}

func (node *Node) AddPendingTransaction(tx *thrylos.Transaction) error {
	if tx == nil {
		return fmt.Errorf("cannot add nil transaction")
	}

	log.Printf("=== Starting AddPendingTransaction ===")
	log.Printf("Transaction ID: %s", tx.Id)

	// Enhanced validation with logging
	if tx.Id == "" {
		log.Printf("Error: Transaction ID is empty")
		return fmt.Errorf("transaction ID cannot be empty")
	}
	if tx.Sender == "" {
		log.Printf("Error: Transaction sender is empty")
		return fmt.Errorf("transaction sender cannot be empty")
	}

	// Log transaction details
	log.Printf("Transaction Details:")
	log.Printf("- Sender: %s", tx.Sender)
	log.Printf("- Gas Fee: %d nanoTHRYLOS (%.7f THRYLOS)", tx.GasFee, float64(tx.GasFee)/1e7)
	log.Printf("- Timestamp: %d", tx.Timestamp)

	// Log inputs
	log.Printf("Inputs:")
	var totalInput int64
	for i, input := range tx.Inputs {
		totalInput += input.Amount
		log.Printf("  [%d] Address: %s, Amount: %d nanoTHRYLOS (%.7f THRYLOS)",
			i, input.OwnerAddress, input.Amount, float64(input.Amount)/1e7)
	}

	// Log outputs
	log.Printf("Outputs:")
	var totalOutput int64
	for i, output := range tx.Outputs {
		totalOutput += output.Amount
		log.Printf("  [%d] Address: %s, Amount: %d nanoTHRYLOS (%.7f THRYLOS)",
			i, output.OwnerAddress, output.Amount, float64(output.Amount)/1e7)
	}

	// Log totals
	log.Printf("Total Input: %d nanoTHRYLOS (%.7f THRYLOS)", totalInput, float64(totalInput)/1e7)
	log.Printf("Total Output: %d nanoTHRYLOS (%.7f THRYLOS)", totalOutput, float64(totalOutput)/1e7)
	log.Printf("Total with Gas: %d nanoTHRYLOS (%.7f THRYLOS)",
		totalOutput+int64(tx.GasFee), float64(totalOutput+int64(tx.GasFee))/1e7)

	node.Blockchain.Mu.Lock()
	defer node.Blockchain.Mu.Unlock()

	// Check for duplicates with logging
	for _, pendingTx := range node.Blockchain.PendingTransactions {
		if pendingTx.Id == tx.Id {
			log.Printf("Warning: Transaction %s already exists in pending pool, skipping", tx.Id)
			return nil
		}
	}

	// Add to pending transactions
	node.Blockchain.PendingTransactions = append(node.Blockchain.PendingTransactions, tx)
	log.Printf("Transaction %s successfully added to pending pool. Total pending: %d",
		tx.Id, len(node.Blockchain.PendingTransactions))

	// Update transaction status
	if err := node.Blockchain.UpdateTransactionStatus(tx.Id, "pending", nil); err != nil {
		log.Printf("Warning: Error updating transaction status: %v", err)
	} else {
		log.Printf("Transaction status updated to 'pending'")
	}

	// Trigger block creation
	log.Printf("Triggering block creation for transaction %s", tx.Id)
	go node.TriggerBlockCreation()

	log.Printf("=== Completed AddPendingTransaction ===")
	return nil
}

func calculateTotalAmount(outputs []*thrylos.UTXO) int64 {
	var total int64
	for _, utxo := range outputs {
		total += int64(utxo.Amount)
	}
	return total
}

// Add this method to periodically check and create blocks
func (node *Node) StartBlockCreationTimer() {
	ticker := time.NewTicker(1 * time.Minute) // Adjust time as needed
	go func() {
		for range ticker.C {
			if len(node.PendingTransactions) > 0 {
				node.TriggerBlockCreation()
			}
		}
	}()
}

// Add this method to your Node struct
func (node *Node) TriggerBlockCreation() {
	log.Println("Triggering block creation due to full pending transaction pool")

	node.Mu.Lock()
	pendingCount := len(node.PendingTransactions)
	node.Mu.Unlock()

	log.Printf("Current pending transactions before processing: %d", pendingCount)

	validator := node.Blockchain.GetCurrentValidator()
	log.Printf("Selected validator: %s", validator)

	newBlock, err := node.Blockchain.ProcessPendingTransactions(validator)
	if err != nil {
		log.Printf("Error creating new block: %v", err)
	} else if newBlock != nil {
		log.Printf("New block created successfully: Index=%d, Hash=%s, Transactions=%d",
			newBlock.Index, newBlock.Hash, len(newBlock.Transactions))
	} else {
		log.Println("No new block created")
	}

	node.Mu.Lock()
	remainingPending := len(node.PendingTransactions)
	node.Mu.Unlock()

	log.Printf("Remaining pending transactions after processing: %d", remainingPending)
}

func (bc *Blockchain) GetCurrentValidator() string {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	if len(bc.ActiveValidators) == 0 {
		log.Println("Warning: No active validators available. Attempting to add genesis account as validator.")
		bc.Mu.RUnlock()
		bc.Mu.Lock()
		bc.ActiveValidators = append(bc.ActiveValidators, bc.GenesisAccount)
		bc.Mu.Unlock()
		bc.Mu.RLock()
	}

	if len(bc.ActiveValidators) == 0 {
		log.Println("Error: Still no active validators available after adding genesis account.")
		return ""
	}

	// Use a combination of time and block height for selection
	currentTime := time.Now().UnixNano()
	currentHeight := len(bc.Blocks)
	combinedFactor := currentTime + int64(currentHeight)

	index := combinedFactor % int64(len(bc.ActiveValidators))
	selectedValidator := bc.ActiveValidators[index]

	log.Printf("Selected validator: %s (index: %d out of %d)", selectedValidator, index, len(bc.ActiveValidators))

	return selectedValidator
}

// BroadcastTransaction sends a transaction to all peers in the network. This is part of the transaction
// propagation mechanism, ensuring that all nodes are aware of new transactions.
func (node *Node) BroadcastTransaction(tx *thrylos.Transaction) error {
	txData, err := json.Marshal(tx)
	if err != nil {
		fmt.Println("Failed to serialize transaction:", err)
		return err
	}

	// Iterating through peers and broadcasting the transaction
	var broadcastErr error
	for _, peer := range node.Peers {
		url := fmt.Sprintf("http://%s/transaction", peer)
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(txData))
		if err != nil {
			fmt.Println("Failed to post transaction to peer:", err)
			broadcastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			fmt.Printf("Received non-OK response when broadcasting transaction to peer: %s, Status: %s\n", peer, resp.Status)
			broadcastErr = fmt.Errorf("failed to broadcast to peer %s, received status %s", peer, resp.Status)
		}
		resp.Body.Close()
	}
	return broadcastErr
}

// BroadcastBlock sends a block to all peers in the network. This is part of the block propagation mechanism,
// ensuring that all nodes are aware of new blocks added to the blockchain.
func (node *Node) BroadcastBlock(block *Block) {
	blockData, err := json.Marshal(block)
	if err != nil {
		fmt.Println("Failed to serialize block:", err)
		return
	}

	for _, peer := range node.Peers {
		resp, err := http.Post(peer+"/block", "application/json", bytes.NewBuffer(blockData))
		if err != nil {
			fmt.Printf("Failed to post block to peer %s: %v\n", peer, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Received non-OK response when broadcasting block to peer %s: %s\n", peer, resp.Status)
		}
		resp.Body.Close() // Close the response body to prevent resource leaks
	}
}

// Synchronizing the Blockchain

// SyncBlockchain synchronizes the node's blockchain with its peers. It fetches blocks from peer nodes to ensure
// the node has the most current and accurate version of the blockchain.
func (node *Node) SyncBlockchain() {
	for _, peer := range node.Peers {
		resp, err := http.Get(peer + "/blockchain")
		if err != nil {
			fmt.Println("Failed to get blockchain from peer:", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Non-OK HTTP status from peer:", resp.StatusCode)
			resp.Body.Close() // Close immediately after checking the status
			continue
		}

		var peerBlockchain Blockchain
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&peerBlockchain)
		resp.Body.Close() // Close as soon as the body is no longer needed

		if err != nil {
			fmt.Println("Failed to deserialize blockchain:", err)
			continue
		}

		// Update blockchain block by block
		if len(peerBlockchain.Blocks) > len(node.Blockchain.Blocks) {
			for i := len(node.Blockchain.Blocks); i < len(peerBlockchain.Blocks); i++ {
				// Optionally, add validation for each new block here
				node.Blockchain.Blocks = append(node.Blockchain.Blocks, peerBlockchain.Blocks[i])
			}
		}
	}
}

func ConvertJSONToProto(jsonTx thrylos.TransactionJSON) *thrylos.Transaction {
	tx := &thrylos.Transaction{
		Id:        jsonTx.ID,
		Timestamp: jsonTx.Timestamp,
		Signature: []byte(jsonTx.Signature),
	}

	for _, input := range jsonTx.Inputs {
		tx.Inputs = append(tx.Inputs, &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         input.Index,
			OwnerAddress:  input.OwnerAddress,
			Amount:        input.Amount,
		})
	}

	for _, output := range jsonTx.Outputs {
		tx.Outputs = append(tx.Outputs, &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         output.Index,
			OwnerAddress:  output.OwnerAddress,
			Amount:        output.Amount,
		})
	}

	return tx
}

// Assuming this is part of the Node struct
func (node *Node) GetBlockCount() int {
	return node.Blockchain.GetBlockCount()
}

// This handler could expose details about validators, their stakes, the votes they've cast for the most recent blocks, and potentially their historical performance or participation rates.

func (node *Node) ConsensusInfoHandler(w http.ResponseWriter, r *http.Request) {
	var validators []struct {
		Address string `json:"address"`
		Stake   int64  `json:"stake"`
		Votes   []Vote `json:"votes"`
	}
	// Gathering data for each stakeholder
	for address, stake := range node.Blockchain.Stakeholders {
		votes := []Vote{}
		for _, vote := range node.Votes {
			if vote.Validator == address {
				votes = append(votes, vote)
			}
		}
		validators = append(validators, struct {
			Address string `json:"address"`
			Stake   int64  `json:"stake"`
			Votes   []Vote `json:"votes"`
		}{
			Address: address,
			Stake:   stake,
			Votes:   votes,
		})
	}
	// Marshal and send the data
	response, err := json.Marshal(validators)
	if err != nil {
		http.Error(w, "Failed to serialize consensus information", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// This endpoint allows nodes to register themselves as validators, specifying necessary credentials or details.

func (node *Node) RegisterValidatorHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address   string `json:"address"`
		PublicKey string `json:"publicKey"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TO DO - Set the Stake amount for the validators

	// Verify the requester has sufficient stake
	// stake, err := node.Blockchain.GetStake(req.Address)
	// if err != nil {
	// 	http.Error(w, "Failed to retrieve stake: "+err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// minStake := node.Blockchain.GetMinStakeForValidator()
	// if stake.Cmp(minStake) < 0 {
	// 	http.Error(w, "Insufficient stake to become a validator", http.StatusBadRequest)
	// 	return
	// }

	// Register the validator without bypassing stake check
	if err := node.Blockchain.RegisterValidator(req.Address, req.PublicKey, false); err != nil {
		http.Error(w, "Failed to register as validator: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registered as validator successfully"))
}

// This endpoint allows stakeholders to modify their stakes in the network.

func (node *Node) UpdateStakeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount"` // Positive to increase, negative to decrease
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := node.Blockchain.UpdateStake(req.Address, req.Amount); err != nil {
		http.Error(w, "Failed to update stake: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Stake updated successfully"))
}

// This endpoint facilitates the delegation of stakes from one user to another, specifying a validator.

func (node *Node) DelegateStakeHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Amount int64  `json:"amount"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := node.Blockchain.DelegateStake(req.From, req.To, req.Amount); err != nil {
		http.Error(w, "Failed to delegate stake: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Stake delegated successfully"))
}

func sendJSONErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

var _ shared.GasEstimator = &Node{} // Ensures Node implements the GasEstimator interface

const MinTransactionAmount int64 = 1 * NanoThrylosPerThrylos // 1 THRYLOS in nanoTHRYLOS

func (n *Node) ProcessSignedTransactionHandler(w http.ResponseWriter, r *http.Request) {
	// Handle OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if n.Database == nil {
		log.Printf("Error: Database interface is nil in ProcessSignedTransactionHandler")
		sendJSONErrorResponse(w, "Internal server error: Database not initialized", http.StatusInternalServerError)
		return
	}
	log.Printf("Database is initialized in ProcessSignedTransactionHandler")

	var requestData struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		sendJSONErrorResponse(w, "Invalid request format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Parse the JWT without verifying
	token, _, err := new(jwt.Parser).ParseUnverified(requestData.Token, jwt.MapClaims{})
	if err != nil {
		sendJSONErrorResponse(w, "Invalid token format: "+err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		sendJSONErrorResponse(w, "Invalid token claims", http.StatusBadRequest)
		return
	}

	// Extract the sender from the claims
	sender, ok := claims["sender"].(string)
	if !ok {
		sendJSONErrorResponse(w, "Invalid sender in token", http.StatusBadRequest)
		return
	}

	// Fetch the public key for the sender
	publicKey, err := n.RetrievePublicKey(sender)
	if err != nil {
		sendJSONErrorResponse(w, "Could not retrieve public key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify the JWT signature
	parts := strings.Split(requestData.Token, ".")
	if len(parts) != 3 {
		sendJSONErrorResponse(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		sendJSONErrorResponse(w, "Invalid signature encoding: "+err.Error(), http.StatusBadRequest)
		return
	}

	message := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(publicKey, message, signatureBytes) {
		log.Printf("JWT signature verification failed for sender: %s", sender)
		sendJSONErrorResponse(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Parse transaction data from claims
	var transactionData shared.Transaction
	transactionData.ID = claims["id"].(string)
	transactionData.Sender = claims["sender"].(string)

	if gasFeeFloat, ok := claims["gasfee"].(float64); ok {
		transactionData.GasFee = int(gasFeeFloat)
	} else {
		sendJSONErrorResponse(w, "Invalid gasfee in token", http.StatusBadRequest)
		return
	}

	if timestampFloat, ok := claims["timestamp"].(float64); ok {
		transactionData.Timestamp = int64(timestampFloat)
	} else {
		sendJSONErrorResponse(w, "Invalid timestamp in token", http.StatusBadRequest)
		return
	}

	// Parse inputs and outputs
	inputsJSON, err := json.Marshal(claims["inputs"])
	if err != nil {
		sendJSONErrorResponse(w, "Invalid inputs in token: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(inputsJSON, &transactionData.Inputs); err != nil {
		sendJSONErrorResponse(w, "Failed to parse inputs: "+err.Error(), http.StatusBadRequest)
		return
	}

	outputsJSON, err := json.Marshal(claims["outputs"])
	if err != nil {
		sendJSONErrorResponse(w, "Invalid outputs in token: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(outputsJSON, &transactionData.Outputs); err != nil {
		sendJSONErrorResponse(w, "Failed to parse outputs: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Transaction inputs before conversion:")
	for i, input := range transactionData.Inputs {
		log.Printf("Input %d: OwnerAddress=%s, Amount=%d", i, input.OwnerAddress, input.Amount)
	}

	thrylosTx := shared.SharedToThrylos(&transactionData)
	if thrylosTx == nil {
		sendJSONErrorResponse(w, "Failed to convert transaction data", http.StatusInternalServerError)
		return
	}

	// Add these logs after conversion
	log.Printf("Transaction inputs after conversion:")
	for i, input := range thrylosTx.Inputs {
		log.Printf("Input %d: OwnerAddress=%s, Amount=%d", i, input.OwnerAddress, input.Amount)
	}

	log.Printf("Transaction data before conversion - Sender: %s", transactionData.Sender)
	log.Printf("Transaction after conversion - Sender: %s", thrylosTx.Sender)

	// Validate balance and transaction (this includes address validation)
	balance, err := n.GetBalance(transactionData.Sender)
	if err != nil {
		log.Printf("Failed to fetch balance for address %s: %v", transactionData.Sender, err)
		sendJSONErrorResponse(w, "Failed to fetch balance: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := shared.ValidateAndConvertTransaction(thrylosTx, n.Database, publicKey, n, balance); err != nil {
		log.Printf("Failed to validate transaction: %v", err)
		sendJSONErrorResponse(w, fmt.Sprintf("Failed to validate transaction: %v", err), http.StatusBadRequest)
		return
	}

	// Add to pending transactions
	if err := n.AddPendingTransaction(thrylosTx); err != nil {
		log.Printf("Failed to add transaction to pending transactions: %v", err)
		sendJSONErrorResponse(w, "Failed to add transaction to pending pool: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Collect addresses for balance updates
	addresses := make(map[string]bool)
	addresses[transactionData.Sender] = true
	for _, output := range transactionData.Outputs {
		addresses[output.OwnerAddress] = true
	}

	// Queue initial balance updates and notifications
	for address := range addresses {
		n.balanceUpdateQueue.queue <- BalanceUpdateRequest{
			Address: address,
			Retries: 3,
		}
	}

	// Schedule delayed balance check to ensure transaction processing is complete
	time.AfterFunc(2*time.Second, func() {
		for address := range addresses {
			balance, err := n.GetBalance(address)
			if err != nil {
				log.Printf("Error getting delayed balance for %s: %v", address, err)
				continue
			}
			n.notifyBalanceUpdate(address, balance)
		}
	})

	if err := n.BroadcastTransaction(thrylosTx); err != nil {
		log.Printf("Failed to broadcast transaction: %v", err)
		sendErrorResponse(w, "Failed to broadcast transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sendResponseProcess(w, map[string]string{
		"message": fmt.Sprintf("Transaction %s processed successfully", transactionData.ID),
	})
}

func (n *Node) processBalanceUpdateQueue() {
	for request := range n.balanceUpdateQueue.queue {
		balance, err := n.GetBalance(request.Address)
		if err != nil {
			log.Printf("Error processing balance update for %s: %v", request.Address, err)
			continue
		}

		n.notifyBalanceUpdate(request.Address, balance)
	}
}

func (n *Node) validateTransactionAddresses(tx *shared.Transaction) error {
	// Validate sender
	_, err := n.Database.RetrievePublicKeyFromAddress(tx.Sender)
	if err != nil {
		log.Printf("Invalid sender address %s: %v", tx.Sender, err)
		return fmt.Errorf("invalid sender address: %v", err)
	}

	// Validate all output addresses
	for _, output := range tx.Outputs {
		_, err := n.Database.RetrievePublicKeyFromAddress(output.OwnerAddress)
		if err != nil {
			log.Printf("Invalid output address %s: %v", output.OwnerAddress, err)
			return fmt.Errorf("invalid output address %s: %v", output.OwnerAddress, err)
		}
	}

	return nil
}

func (node *Node) validateRecipientAddress(address string) error {
	if address == "" {
		return fmt.Errorf("empty recipient address")
	}

	// Only validate that the address exists in the system
	_, err := node.Database.RetrievePublicKeyFromAddress(address)
	if err != nil {
		return fmt.Errorf("recipient not registered: %v", err)
	}

	// Remove WebSocket connection check - recipients don't need to be connected
	return nil
}

func (n *Node) updateBalances(tx *thrylos.Transaction) error {
	// Update sender's balance
	senderBalance, err := n.Blockchain.GetBalance(tx.Sender)
	if err != nil {
		return fmt.Errorf("failed to get sender balance: %v", err)
	}
	log.Printf("Updated sender (%s) balance: %s", tx.Sender, senderBalance.String())

	// Update recipients' balances
	for _, output := range tx.Outputs {
		recipientBalance, err := n.Blockchain.GetBalance(output.OwnerAddress)
		if err != nil {
			return fmt.Errorf("failed to get recipient balance: %v", err)
		}
		log.Printf("Updated recipient (%s) balance: %s", output.OwnerAddress, recipientBalance.String())
	}

	return nil
}

func (node *Node) notifyBalanceUpdate(address string, balance int64) {
	node.WebSocketMutex.RLock()
	conn, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if !exists || conn == nil {
		log.Printf("Address %s is offline - balance update will be received when they reconnect", address)
		return
	}

	// Use the protobuf-generated message type
	balanceMsg := &thrylos.BalanceMessage{
		BlockchainAddress: address,
		Balance:           balance,
		BalanceThrylos:    float64(balance) / 1e7,
	}

	msgBytes, err := json.Marshal(balanceMsg)
	if err != nil {
		log.Printf("Error marshaling balance message for %s: %v", address, err)
		return
	}

	select {
	case conn.send <- msgBytes:
		log.Printf("Successfully sent balance update for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
			address, balance, balanceMsg.BalanceThrylos)
	default:
		log.Printf("Channel full or closed for %s - balance update skipped", address)
	}
}

func (node *Node) ProcessConfirmedTransactions(block *Block) {
	log.Printf("Processing confirmed transactions for block %s", block.Hash)

	// Track all addresses that need updates
	addressesToUpdate := make(map[string]bool)

	for _, tx := range block.Transactions {
		// Add sender to update list
		addressesToUpdate[tx.Sender] = true

		// Add all recipients to update list
		for _, output := range tx.Outputs {
			addressesToUpdate[output.OwnerAddress] = true
		}
	}

	// Send updates for all affected addresses
	for address := range addressesToUpdate {
		// Try multiple times with exponential backoff
		go func(addr string) {
			for i := 0; i < 3; i++ {
				if err := node.SendBalanceUpdate(addr); err == nil {
					return
				}
				time.Sleep(time.Duration(math.Pow(2, float64(i))) * time.Second)
			}
			log.Printf("Failed to update balance for address %s after 3 attempts", addr)
		}(address)
	}
}

func (node *Node) UpdateBalanceAsync(address string) {
	go func() {
		retries := 0
		maxRetries := 5
		for retries < maxRetries {
			balance, err := node.Blockchain.GetBalance(address)
			if err != nil {
				log.Printf("Error getting balance for %s: %v", address, err)
				retries++
				time.Sleep(time.Duration(math.Pow(2, float64(retries))) * time.Second)
				continue
			}

			if err := node.SendBalanceUpdate(address); err == nil {
				log.Printf("Balance updated successfully for %s: %d", address, balance)
				return
			}
			retries++
			time.Sleep(time.Duration(math.Pow(2, float64(retries))) * time.Second)
		}
		log.Printf("Failed to update balance for %s after %d attempts", address, maxRetries)
	}()
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Helper function to send JSON responses
func sendResponseProcess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

// Helper function to fetch gas estimate
func (n *Node) FetchGasEstimate(dataSize int, balance int64) (int, error) {
	url := fmt.Sprintf("%s?dataSize=%d&balance=%d", "https://node.thrylos.org/gas-fee", dataSize, balance)
	log.Printf("Fetching gas estimate from URL: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("HTTP request failed: %v", err)
		return 0, err
	}
	defer resp.Body.Close()

	log.Printf("Received response with status code: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch gas estimate, status code: %d", resp.StatusCode)
		return 0, fmt.Errorf("failed to fetch gas estimate, status code: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Error decoding JSON response: %v", err)
		return 0, err
	}

	log.Printf("Gas estimate received: %v", result)

	if gasFeeValue, exists := result["gasFee"]; exists {
		var gasEstimate int

		switch v := gasFeeValue.(type) {
		case float64:
			gasEstimate = int(v)
		case string:
			parsedValue, err := strconv.Atoi(v)
			if err != nil {
				log.Printf("Error parsing gas fee string: %v", err)
				return 0, fmt.Errorf("invalid gas fee format: %v", err)
			}
			gasEstimate = parsedValue
		default:
			log.Printf("Unexpected type for gas fee: %T", v)
			return 0, fmt.Errorf("unexpected gas fee type: %T", v)
		}

		log.Printf("Gas estimate found: %d (0.%06d THRYLOS)", gasEstimate, gasEstimate)
		return gasEstimate, nil
	} else {
		log.Printf("Gas estimate not found in the response: %v", result)
		return 0, fmt.Errorf("gas estimate not found in response")
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func (n *Node) logError(stage string, err error) {
	log.Printf("[%s] error: %v", stage, err)
}

func publicKeyToBech32(pubKeyBase64 string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		log.Printf("Failed to decode base64 public key: %v", err)
		return "", err
	}

	data, err := bech32.ConvertBits(pubKeyBytes, 8, 5, true)
	if err != nil {
		log.Printf("Failed to convert bits for Bech32: %v", err)
		return "", err
	}

	bech32Address, err := bech32.Encode("tl1", data)
	if err != nil {
		log.Printf("Failed to encode Bech32 address: %v", err)
		return "", err
	}

	log.Printf("Generated Bech32 address: %s", bech32Address)
	return bech32Address, nil
}

func GetBlockchainAddressByUID(supabaseClient *supabase.Client, userID string) (string, error) {
	data, _, err := supabaseClient.From("blockchain_info").
		Select("blockchain_address", "exact", false).
		Eq("user_id", userID).
		Single().
		Execute()

	if err != nil {
		fmt.Println("Error executing query:", err)
		return "", fmt.Errorf("error executing query: %v", err)
	}

	var result struct {
		PublicKeyBase64 string `json:"blockchain_address"`
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		fmt.Println("Error unmarshaling data:", err)
		return "", fmt.Errorf("public key not found for user %s", userID)
	}

	return result.PublicKeyBase64, nil
}

func (node *Node) GasEstimateHandler(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	log.Printf("GasEstimateHandler called with method: %s", r.Method)

	// Handle OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Ensure the request method is GET
	if r.Method != http.MethodGet {
		log.Printf("Invalid method for GasEstimateHandler: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get and validate dataSize parameter
	dataSizeStr := r.URL.Query().Get("dataSize")
	if dataSizeStr == "" {
		log.Print("dataSize parameter is missing")
		http.Error(w, "dataSize parameter is missing", http.StatusBadRequest)
		return
	}

	dataSize, err := strconv.Atoi(dataSizeStr)
	if err != nil {
		log.Printf("Invalid dataSize parameter: %v", err)
		http.Error(w, "Invalid dataSize parameter", http.StatusBadRequest)
		return
	}

	// Calculate gas
	gas := CalculateGas(dataSize, 0)

	// Prepare the response
	response := struct {
		GasFee     int    `json:"gasFee"`
		GasFeeUnit string `json:"gasFeeUnit"`
	}{
		GasFee:     gas,
		GasFeeUnit: "nanoTHRYLOS",
	}

	// Set content type and encode response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Gas fee estimate sent: %d for data size: %d", gas, dataSize)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("CORS middleware invoked")

		// Allow requests from specific origins
		allowedOrigins := []string{"http://localhost:3000", "https://your-production-domain.com"}
		origin := r.Header.Get("Origin")
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}

		// Set other CORS headers
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			log.Println("Preflight request received")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Set content type for the response
		w.Header().Set("Content-Type", "application/json")

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func (node *Node) GetUTXOsForAddressHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GetUTXOsForAddressHandler called with method: %s", r.Method)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("Request URL: %s", r.URL.String())
	address := r.URL.Query().Get("address")
	if address == "" {
		log.Printf("Address parameter is missing")
		http.Error(w, "Address parameter is missing", http.StatusBadRequest)
		return
	}

	log.Printf("Fetching UTXOs for address: %s", address)
	utxos, err := node.Blockchain.GetUTXOsForAddress(address)
	if err != nil {
		log.Printf("Error fetching UTXOs from database for address %s: %v", address, err)
		http.Error(w, fmt.Sprintf("Error fetching UTXOs: %v", err), http.StatusInternalServerError)
		return
	}

	if len(utxos) == 0 {
		log.Printf("No UTXOs found for address: %s", address)
		http.Error(w, "No UTXOs found", http.StatusNotFound)
		return
	} else {
		log.Printf("Retrieved %d UTXOs for address %s", len(utxos), address)
	}

	response, err := json.Marshal(utxos)
	if err != nil {
		log.Printf("Failed to serialize UTXOs for address %s: %v", address, err)
		http.Error(w, "Failed to serialize UTXOs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (node *Node) FundWalletHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	// Debugging log, consider using a conditional flag or environment-based logging.
	fmt.Printf("Attempting to fund wallet: Address=%s, Amount=%d\n", request.Address, request.Amount)

	// Transfer funds from the genesis account
	if err := node.Blockchain.TransferFunds("", request.Address, request.Amount); err != nil {
		http.Error(w, fmt.Sprintf("Failed to fund wallet: %v", err), http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"message": fmt.Sprintf("Funded wallet with %d successfully", request.Amount),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) // Consider error handling for JSON encoding
}

func (node *Node) CheckPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	publicKey := r.URL.Query().Get("publicKey") // Use r.URL.Query().Get to fetch query parameters
	if publicKey == "" {
		http.Error(w, "Public key parameter is required", http.StatusBadRequest)
		return
	}
	exists, err := node.Blockchain.Database.PublicKeyExists(publicKey)
	if err != nil {
		http.Error(w, "Internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	response := map[string]bool{"exists": exists}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func ThrylosTo(thrylos float64) int64 {
	return int64(thrylos)
}

func (node *Node) RegisterWalletHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("RegisterWalletHandler request received")
	var req struct {
		PublicKey string `json:"publicKey"` // Public key expected to be in base64 format
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Decode base64 string to bytes
	publicKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		log.Printf("Invalid base64 format for public key: %v", err)
		http.Error(w, "Invalid public key format: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Generate Bech32 address from public key
	bech32Address, err := publicKeyToBech32(req.PublicKey)
	if err != nil {
		log.Printf("Failed to convert public key to Bech32 address: %v", err)
		http.Error(w, "Failed to generate Bech32 address: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the Bech32 address is already registered
	addressExists, err := node.Blockchain.Database.Bech32AddressExists(bech32Address)
	if err != nil {
		log.Printf("Failed to check address existence: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if addressExists {
		log.Printf("Blockchain address already registered: %s", bech32Address)
		http.Error(w, "Blockchain address already registered.", http.StatusBadRequest)
		return
	}

	// Ensure there are sufficient funds in the genesis account
	initialBalanceThrylos := 70.0 // 70 THRYLOS
	initialBalanceNano := ThrylosToNanoNode(initialBalanceThrylos)

	currentBalanceNano, genesisExists := node.Blockchain.Stakeholders[node.Blockchain.GenesisAccount]
	if !genesisExists || currentBalanceNano < initialBalanceNano {
		log.Printf("Insufficient funds in genesis account. Required: %d nanoTHRYLOS, Available: %d nanoTHRYLOS", initialBalanceNano, currentBalanceNano)
		http.Error(w, "Insufficient funds in the genesis account.", http.StatusBadRequest)
		return
	}

	// Deduct from genesis and assign to new account
	node.Blockchain.Stakeholders[node.Blockchain.GenesisAccount] -= initialBalanceNano
	node.Blockchain.Stakeholders[bech32Address] = initialBalanceNano

	// Create initial UTXO for the account
	utxo := shared.UTXO{
		OwnerAddress: bech32Address,
		Amount:       initialBalanceNano,
	}
	if err := node.Blockchain.addUTXO(utxo); err != nil {
		http.Error(w, "Failed to create initial UTXO: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := node.Blockchain.Database.InsertOrUpdateEd25519PublicKey(bech32Address, publicKeyBytes); err != nil {
		http.Error(w, "Failed to save public key to database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Created initial UTXO for %s with amount %d nanoTHRYLOS (%.7f THRYLOS)", bech32Address, initialBalanceNano, float64(initialBalanceNano)/NanoThrylosPerThrylos)
	log.Printf("Blockchain address registered and public key saved to database for %s", bech32Address)

	response := struct {
		PublicKey         string        `json:"publicKey"`
		BlockchainAddress string        `json:"blockchainAddress"`
		Balance           int64         `json:"balance"`        // Balance in nanoTHRYLOS
		BalanceThrylos    float64       `json:"balanceThrylos"` // Balance in THRYLOS
		UTXOs             []shared.UTXO `json:"utxos"`
	}{
		PublicKey:         req.PublicKey,
		BlockchainAddress: bech32Address,
		Balance:           initialBalanceNano,
		BalanceThrylos:    initialBalanceThrylos,
		UTXOs:             []shared.UTXO{utxo},
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to serialize response: %v", err)
		http.Error(w, "Failed to serialize wallet data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (node *Node) GetPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address parameter is missing", http.StatusBadRequest)
		return
	}

	publicKey, err := node.RetrievePublicKey(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	response := map[string]string{
		"publicKey": base64.StdEncoding.EncodeToString(publicKey),
	}

	jsonResp, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to serialize public key response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func (node *Node) BlockchainHandler(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(node.Blockchain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (node *Node) BlockHandler(w http.ResponseWriter, r *http.Request) {
	var block Block
	if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	prevBlock, prevIndex, err := node.Blockchain.GetLastBlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get the last block: %v", err), http.StatusInternalServerError)
		return
	}

	if prevBlock != nil && !node.Blockchain.ValidateBlock(&block, prevBlock) {
		http.Error(w, "Block validation failed", http.StatusUnprocessableEntity)
		return
	}
	success, err := node.Blockchain.AddBlock(block.Transactions, block.Validator, block.PrevHash, block.Timestamp)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add block: %v", err), http.StatusInternalServerError)
		return
	}
	if !success {
		http.Error(w, "Failed to add block due to validation or other issues", http.StatusBadRequest)
		return
	}

	if prevBlock != nil {
		log.Printf("Previous Block Index: %d, Block Hash: %s", prevIndex, prevBlock.Hash)
	} else {
		log.Println("No previous block exists.")
	}
	w.WriteHeader(http.StatusCreated)
}

func (node *Node) PeersHandler(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(node.Peers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (node *Node) VoteHandler(w http.ResponseWriter, r *http.Request) {
	var vote Vote
	if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	node.Votes = append(node.Votes, vote)
}

func (node *Node) StatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := node.GetBlockchainStats()
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		http.Error(w, "Failed to serialize blockchain statistics", http.StatusInternalServerError)
		return
	}
	sendResponse(w, statsJSON)
}

func (node *Node) TransactionHandler(w http.ResponseWriter, r *http.Request) {
	var jsonTx thrylos.TransactionJSON
	if err := json.NewDecoder(r.Body).Decode(&jsonTx); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tx := ConvertJSONToProto(jsonTx)

	node.AddPendingTransaction(tx)
	fmt.Printf("Verified and added transaction %s to pending transactions\n", tx.GetId())
	w.WriteHeader(http.StatusCreated)
}

func (node *Node) GetBlockchainAddressHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("userId")
	if uid == "" {
		http.Error(w, "User ID parameter is missing", http.StatusBadRequest)
		return
	}
	blockchainAddress, err := GetBlockchainAddressByUID(node.SupabaseClient, uid)
	if err != nil {
		log.Printf("Failed to retrieve blockchain address for UID %s: %v", uid, err)
		http.Error(w, "Internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if blockchainAddress == "" {
		http.Error(w, "Blockchain address not found", http.StatusNotFound)
		return
	}
	response := map[string]string{"blockchainAddress": blockchainAddress}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to serialize response: %v", err)
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

// Start initializes the HTTP server for the node, setting up endpoints for blockchain, block, peers,
// votes, and transactions handling. It also starts background tasks for discovering peers and counting votes.
func (node *Node) SetupRoutes() *mux.Router {

	r := mux.NewRouter()
	// Apply the middleware to all routes
	r.Use(corsMiddleware)
	// Define handlers for various endpoints
	r.HandleFunc("/block", node.BlockHandler).Methods("POST")
	r.HandleFunc("/blockchain", node.BlockchainHandler).Methods("GET")
	r.HandleFunc("/check-public-key", node.CheckPublicKeyHandler).Methods("GET")
	r.HandleFunc("/consensus-info", node.ConsensusInfoHandler).Methods("GET")
	r.HandleFunc("/delegate-stake", node.DelegateStakeHandler).Methods("POST")
	r.HandleFunc("/fund-wallet", node.FundWalletHandler).Methods("POST")
	r.HandleFunc("/gas-fee", node.GasEstimateHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/get-blockchain-address", node.GetBlockchainAddressHandler).Methods("GET")
	r.HandleFunc("/get-publickey", node.GetPublicKeyHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/get-transaction", node.GetTransactionHandler).Methods("GET")
	r.HandleFunc("/get-utxo", node.GetUTXOsForAddressHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/list-transactions-for-block", node.ListTransactionsForBlockHandler).Methods("GET")
	r.HandleFunc("/network-health", node.NetworkHealthHandler).Methods("GET")
	r.HandleFunc("/peers", node.PeersHandler).Methods("GET")
	r.HandleFunc("/process-transaction", node.ProcessSignedTransactionHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/register-public-key", node.RegisterPublicKeyHandler).Methods("POST")
	r.HandleFunc("/register-validator", node.RegisterValidatorHandler).Methods("POST")
	r.HandleFunc("/register-wallet", node.RegisterWalletHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/stats", node.StatsHandler).Methods("GET")
	r.HandleFunc("/transaction", node.TransactionHandler).Methods("POST")
	r.HandleFunc("/update-stake", node.UpdateStakeHandler).Methods("POST")
	r.HandleFunc("/vote", node.VoteHandler).Methods("POST")
	r.HandleFunc("/pending-transactions", node.PendingTransactionsHandler).Methods("GET")
	r.HandleFunc("/ws/balance", node.WebSocketBalanceHandler)

	return r
}

func (node *Node) StartBackgroundTasks() {
	tickerDiscoverPeers := time.NewTicker(10 * time.Minute)
	tickerCountVotes := time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-tickerDiscoverPeers.C:
				node.DiscoverPeers()
			case <-tickerCountVotes.C:
				node.CountVotes()
			}
		}
	}()
}
