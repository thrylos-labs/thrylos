package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	firebase "firebase.google.com/go"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/gibson042/canonicaljson-go"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"google.golang.org/api/option"

	"github.com/joho/godotenv"
)

// Vote represents a vote cast by a validator for a specific block. It includes the block hash being voted for,
// the validator's address, and the stake the validator had at the time of voting. This is used in consensus mechanisms
// that involve staking and voting for block validity.
type Vote struct {
	BlockHash string // Hash of the block that is being voted for.
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
	FirebaseApp    *firebase.App
}

// Hold the chain ID and then proviude a method to set it
func (n *Node) SetChainID(chainID string) {
	n.chainID = chainID
}

func loadEnv() {
	env := os.Getenv("ENV")
	var envPath string
	if env == "production" {
		envPath = "../../.env.prod" // Ensure this is the correct path relative to where the app is run
	} else {
		envPath = "../../.env.dev" // Default to development environment
	}
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	}
}

// NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// blockchain instance for the node and optionally discovers peers if not running in a test environment.
func NewNode(address string, knownPeers []string, dataDir string, shard *Shard, isTest bool) *Node {
	// Load configuration from .env file, particularly for non-test environments
	if !isTest {
		loadEnv() // Dynamically load the correct environment configuration
	}

	// Retrieve the AES key securely from an environment variable, with a fallback for tests
	aesKeyEncoded := os.Getenv("AES_KEY_ENV_VAR")
	if aesKeyEncoded == "" {
		if isTest {
			aesKeyEncoded = "A6uv/jWDTJtCHQe8xvuYjFN7Oxc29ahnaVHDH+zrXfM=" // Ensure this is properly base64-encoded
		} else {
			log.Fatal("AES key is not set in environment variables")
		}
	}

	log.Printf("AES Key from environment: %s", aesKeyEncoded) // Debug output to see what is retrieved

	aesKey, err := base64.StdEncoding.DecodeString(aesKeyEncoded)
	if err != nil {
		log.Fatalf("Failed to decode AES key: %v", err)
	} else {
		log.Println("AES key decoded successfully")
	}

	// Retrieve the URL for gas estimation from an environment variable
	gasEstimateURL := os.Getenv("GAS_ESTIMATE_URL")
	if gasEstimateURL == "" {
		log.Fatal("Gas estimate URL is not set in environment variables. Please configure it before starting.")
	}

	// Assuming you have a way to get or set a default genesis account address
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")
	if genesisAccount == "" {
		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
	}

	ctx := context.Background()
	sa := option.WithCredentialsFile("../../serviceAccountKey.json")

	projectID := os.Getenv("FIREBASE_PROJECT_ID")
	if projectID == "" {
		log.Fatalf("FIREBASE_PROJECT_ID environment variable is not set")
	}

	conf := &firebase.Config{
		ProjectID: projectID,
	}

	firebaseApp, err := firebase.NewApp(ctx, conf, sa)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	bc, err := NewBlockchain(dataDir, aesKey, genesisAccount, firebaseApp) // Pass both dataDir and aesKey to the NewBlockchain function
	if err != nil {
		log.Fatalf("Failed to create new blockchain: %v", err)
	}

	node := &Node{
		Address:          address,
		Peers:            knownPeers,
		Blockchain:       bc,
		Shard:            shard,
		FirebaseApp:      firebaseApp,
		PublicKeyMap:     make(map[string]ed25519.PublicKey), // Initialize the map
		ResponsibleUTXOs: make(map[string]shared.UTXO),
		GasEstimateURL:   gasEstimateURL, // Set the URL in the node struct

	}

	if shard != nil {
		shard.AssignNode(node)
	}

	if !isTest {
		node.DiscoverPeers() // Skip this during tests
	}

	return node
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
func (n *Node) HasBlock(blockHash string) bool {
	for _, block := range n.Blockchain.Blocks {
		if block.Hash == blockHash {
			return true
		}
	}
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
func CalculateGas(dataSize int) int {
	baseFee := 10   // Base fee for transaction processing
	perByteFee := 1 // Fee per byte of transaction data
	return baseFee + (dataSize * perByteFee)
}

// CreateAndBroadcastTransaction creates a new transaction with the specified recipient and amount,
// signs it with the sender's Ed25519 private key, and broadcasts it to the network.
// func (node *Node) CreateAndBroadcastTransaction(recipientAddress string, from *string, amount int, data *[]byte, gas *int) error {
// 	// Retrieve the private key securely
// 	privateKeyBytes, err := node.Database.RetrievePrivateKey(node.Address)
// 	if err != nil {
// 		return fmt.Errorf("failed to retrieve private key: %v", err)
// 	}

// 	ed25519PrivateKey, err := shared.DecodePrivateKey(privateKeyBytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to decode private key: %v", err)
// 	}

// 	// Prepare AES key if data is provided
// 	var aesKey []byte
// 	if data != nil {
// 		aesKey = *data
// 	}

// 	// Use the gas estimator to fetch the gas fee
// 	var gasFee int
// 	if gas != nil {
// 		gasFee = *gas
// 	} else if data != nil {
// 		gasFee, err = node.FetchGasEstimate(len(*data))
// 		if err != nil {
// 			return fmt.Errorf("failed to fetch gas estimate: %v", err)
// 		}
// 	} else {
// 		gasFee, err = node.FetchGasEstimate(0) // Default base fee if no data is present
// 		if err != nil {
// 			return fmt.Errorf("failed to fetch gas estimate: %v", err)
// 		}
// 	}

// 	// Total amount includes the gas fee
// 	totalAmount := amount + gasFee

// 	// Collect inputs for the transaction
// 	inputs, change, err := node.CollectInputsForTransaction(totalAmount, node.Address)
// 	if err != nil {
// 		return fmt.Errorf("failed to collect inputs for transaction: %v", err)
// 	}

// 	// Prepare outputs
// 	outputs := []shared.UTXO{{OwnerAddress: recipientAddress, Amount: amount}}
// 	if change > 0 {
// 		outputs = append(outputs, shared.UTXO{OwnerAddress: node.Address, Amount: change})
// 	}

// 	// Generate a unique transaction ID
// 	transactionID, err := shared.GenerateTransactionID(inputs, outputs, node.Address, amount, gasFee)
// 	if err != nil {
// 		return fmt.Errorf("failed to generate transaction ID: %v", err)
// 	}

// 	// Create and sign the transaction, passing the GasEstimator
// 	transaction, err := shared.CreateAndSignTransaction(transactionID, node.Address, inputs, outputs, ed25519PrivateKey, aesKey, node)
// 	if err != nil {
// 		return fmt.Errorf("failed to create and sign transaction: %v", err)
// 	}

// 	// Broadcast the transaction
// 	node.BroadcastTransaction(transaction)
// 	return nil
// }

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
func (node *Node) ListTransactionsForBlockHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// Allows users to register their public keys with Thrylos, enssential for transactions where public keys are needed
func (node *Node) RegisterPublicKeyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

func (node *Node) GetPendingTransactions() []*thrylos.Transaction {
	return node.PendingTransactions
}

func (node *Node) PendingTransactionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pendingTransactions := node.GetPendingTransactions()
		txData, err := json.Marshal(pendingTransactions)
		if err != nil {
			http.Error(w, "Failed to serialize pending transactions", http.StatusInternalServerError)
			return
		}
		sendResponse(w, txData)
	}
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

// GetTransactionHandler retrieves a specific transaction by ID.
func (node *Node) GetTransactionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// Report the health of the node and its connectivity with other peers
func (node *Node) NetworkHealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		response, err := json.Marshal(healthInfo)
		if err != nil {
			http.Error(w, "Failed to serialize health information", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}
}

func (node *Node) GetBalance(address string) (int64, error) {
	balance, err := node.Blockchain.GetBalance(address)
	return int64(balance), err // Cast the balance to int64 if necessary
}

func (node *Node) GetBalanceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("GetBalanceHandler called")
		address := r.URL.Query().Get("address")
		if address == "" {
			response := `{"error":"Address parameter is missing"}`
			log.Println("Sending error response:", response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(response))
			return
		}

		// Optionally validate the address format here if necessary
		if !isValidBech32Address(address) {
			response := fmt.Sprintf(`{"error":"Invalid address format: %s"}`, address)
			log.Println("Sending error response:", response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(response))
			return
		}

		log.Printf("Attempting to get balance for address: %s", address)
		balance, err := node.Blockchain.GetBalance(address)
		if err != nil {
			response := fmt.Sprintf(`{"error":"Failed to get balance for address %s: %v"}`, address, err)
			log.Println("Sending error response:", response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(response))
			return
		}

		log.Printf("Retrieved balance for address %s: %d", address, balance)
		response := map[string]interface{}{
			"address": address,
			"balance": balance,
		}
		responseJSON, _ := json.Marshal(response)
		log.Printf("Sending success response: %s", string(responseJSON))
		w.Header().Set("Content-Type", "application/json")
		w.Write(responseJSON)
	}
}

func isValidBech32Address(address string) bool {
	// Decode the address using the bech32 package
	hrp, decoded, err := bech32.Decode(address)
	if err != nil {
		return false // The address is not valid if it cannot be decoded
	}

	// Optionally check for specific human-readable parts (hrp)
	// For instance, if you expect the hrp to be 'tl', you can check it as follows:
	if hrp != "tl1" {
		return false
	}

	// Check the length of the decoded data; adjust conditions based on your needs
	if len(decoded) == 0 {
		return false
	}

	return true
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
		voteStakes[vote.BlockHash] += vote.Stake
		if voteStakes[vote.BlockHash] >= majorityStake {
			// This block has a majority stake vote
			// Add it to the blockchain and broadcast it
			var majorityBlock *Block // Assume you find this block somehow
			// node.blockchain.AddBlock( /* appropriate arguments */ )
			node.BroadcastBlock(majorityBlock)
			node.Votes = []Vote{} // Clear votes
			break
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
	var totalStake int64

	for _, stake := range bc.Stakeholders {
		totalStake += stake
	}

	if totalStake == 0 {
		fmt.Println("No stake available.")
		return ""
	}

	randStake, err := SecureRandomInt(totalStake)
	if err != nil {
		fmt.Println("Failed to generate secure random number:", err)
		return ""
	}

	for address, stake := range bc.Stakeholders {
		randStake -= stake
		if randStake < 0 {
			return address
		}
	}

	return ""
}

func (node *Node) AddPendingTransaction(tx *thrylos.Transaction) error {
	node.PendingTransactions = append(node.PendingTransactions, tx)
	return nil // Assuming you might want to handle errors in some scenarios
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

func (node *Node) ConsensusInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// This endpoint allows nodes to register themselves as validators, specifying necessary credentials or details.

func (node *Node) RegisterValidatorHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address   string `json:"address"`
			PublicKey string `json:"publicKey"` // Public key to be registered
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if err := node.Blockchain.RegisterValidator(req.Address, req.PublicKey); err != nil {
			http.Error(w, "Failed to register as validator: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Registered as validator successfully"))
	}
}

// This endpoint allows stakeholders to modify their stakes in the network.

func (node *Node) UpdateStakeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// This endpoint facilitates the delegation of stakes from one user to another, specifying a validator.

func (node *Node) DelegateStakeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

var _ shared.GasEstimator = &Node{} // Ensures Node implements the GasEstimator interface

// func (n *Node) ProcessSignedTransactionHandler() http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Read and log the request body
// 		bodyBytes, err := io.ReadAll(r.Body)
// 		if err != nil {
// 			log.Printf("Error reading request body: %v", err)
// 			http.Error(w, "Error reading request body: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		log.Printf("Raw request body: %s", string(bodyBytes))

// 		var transactionData shared.Transaction
// 		if err := json.Unmarshal(bodyBytes, &transactionData); err != nil {
// 			log.Printf("Failed to decode JSON: %v", err)
// 			http.Error(w, "Invalid transaction format: "+err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		// Retrieve the public key
// 		publicKey, err := n.Blockchain.RetrievePublicKey(transactionData.Sender)
// 		if err != nil {
// 			log.Printf("Failed to retrieve public key: %v", err)
// 			http.Error(w, "Failed to retrieve public key: "+err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		// Verify the signature
// 		if !verifySignature(publicKey, transactionData) {
// 			log.Printf("Signature verification failed: %v", err)
// 			http.Error(w, "Signature verification failed", http.StatusUnauthorized)
// 			return
// 		}

// 		log.Println("Signature verified successfully")
// 		fmt.Fprintf(w, "Transaction processed successfully")
// 	}
// }

// func verifySignature(publicKey ed25519.PublicKey, tx shared.Transaction) bool {
// 	message, err := json.Marshal(tx) // Ensure this serialization matches the frontend's
// 	if err != nil {
// 		log.Printf("Error serializing transaction data: %v", err)
// 		return false
// 	}

// 	signature, err := base64.StdEncoding.DecodeString(tx.Signature)
// 	if err != nil {
// 		log.Printf("Error decoding signature: %v", err)
// 		return false
// 	}

// 	if !ed25519.Verify(publicKey, message, signature) {
// 		log.Printf("Failed to verify signature for transaction %s", tx.ID)
// 		return false
// 	}

// 	return true
// }

func (n *Node) ProcessSignedTransactionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read the entire request body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Error reading request body: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Raw request body: %s", string(bodyBytes))
		log.Printf("Serialized data on backend: %s", string(bodyBytes))

		// Deserialize the JSON into the expected structure
		var transactionData shared.Transaction
		if err := json.Unmarshal(bodyBytes, &transactionData); err != nil {
			log.Printf("Failed to decode JSON: %v", err)
			http.Error(w, "Invalid transaction format: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Retrieve the public key based on the sender's address
		publicKey, err := n.RetrievePublicKey(transactionData.Sender)
		if err != nil {
			log.Printf("Failed to retrieve public key: %v", err)
			http.Error(w, "Could not retrieve public key: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Decode the Base64 encoded signature from the transaction data
		sigBytes, err := base64.StdEncoding.DecodeString(transactionData.Signature)
		if err != nil {
			log.Printf("Error decoding signature: %v", err)
			http.Error(w, "Signature decoding error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Received transaction data: %+v", transactionData)

		// Verify the signature against the data using the public key
		if !verifySignature(transactionData, sigBytes, publicKey) {
			log.Printf("Invalid signature for transaction: %+v", transactionData)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// Convert shared.Transaction to thrylos.Transaction
		thrylosTx := shared.SharedToThrylos(&transactionData)
		if thrylosTx == nil {
			http.Error(w, "Failed to convert transaction data", http.StatusInternalServerError)
			return
		}

		// Process the transaction in the system
		if err := shared.ProcessTransaction(thrylosTx, n.Database, publicKey, n); err != nil {
			log.Printf("Failed to process transaction: %v", err)
			http.Error(w, fmt.Sprintf("Failed to process transaction: %v", err), http.StatusInternalServerError)
			return
		}

		// Optionally add transaction to pending transactions
		if err := n.AddPendingTransaction(thrylosTx); err != nil {
			log.Printf("Failed to add transaction to pending transactions: %v", err)
			http.Error(w, "Failed to add transaction to pending pool: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Broadcast the transaction to the network if necessary
		if err := n.BroadcastTransaction(thrylosTx); err != nil {
			log.Printf("Failed to broadcast transaction: %v", err)
			http.Error(w, "Failed to broadcast transaction: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response back to the client
		sendResponseProcess(w, []byte(fmt.Sprintf("Transaction %s processed successfully", transactionData.ID)))
	}
}

// Helper function to send JSON responses
func sendResponseProcess(w http.ResponseWriter, message []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(message)
}

// Signature verification function with detailed logging and excluding the signature field
// This function should strip out the signature from the transaction data before verification.
func verifySignature(txData shared.Transaction, sigBytes []byte, publicKey ed25519.PublicKey) bool {
	// Remove signature from the data to be verified
	txData.Signature = ""

	canonicalData, err := canonicaljson.Marshal(txData)
	if err != nil {
		log.Printf("Error serializing data for verification: %v", err)
		return false
	}

	log.Printf("Canonical data being verified (excluding signature): %s", string(canonicalData))
	log.Printf("Signature bytes: %v", sigBytes)
	log.Printf("Public key used: %v", publicKey)

	isValid := ed25519.Verify(publicKey, canonicalData, sigBytes)
	if !isValid {
		log.Printf("Signature verification failed for modified data: %s", string(canonicalData))
	}
	return isValid
}

// Helper function to fetch gas estimate
func (n *Node) FetchGasEstimate(dataSize int) (int, error) {
	url := fmt.Sprintf("%s?dataSize=%d", n.GasEstimateURL, dataSize)
	fmt.Printf("Fetching gas estimate from URL: %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("HTTP request failed: %v\n", err)
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to fetch gas estimate, status code: %d", resp.StatusCode)
	}

	var result map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	return result["gasEstimate"], nil
}

func (node *Node) GasEstimateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		dataSizeStr := r.URL.Query().Get("dataSize")
		if dataSizeStr == "" {
			http.Error(w, "dataSize parameter is missing", http.StatusBadRequest)
			return
		}

		dataSize, err := strconv.Atoi(dataSizeStr)
		if err != nil {
			http.Error(w, "Invalid dataSize parameter", http.StatusBadRequest)
			return
		}

		// Calculate gas using the provided data size
		gas := CalculateGas(dataSize)

		// Prepare the response
		response := struct {
			GasFee int `json:"gasFee"`
		}{
			GasFee: gas,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func (node *Node) GetUTXOsForAddressHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf("Request URL: %s", r.URL.String())
		address := r.URL.Query().Get("address")
		if address == "" {
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
}

func (n *Node) logError(stage string, err error) {
	log.Printf("[%s] error: %v", stage, err)
}

// FundWalletHandler transfers a predefined amount from the genesis account to a new user's wallet.
func (node *Node) FundWalletHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

func publicKeyToBech32(pubKeyHex string) (string, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", err
	}

	// Convert byte array to 5-bit base32
	data, err := bech32.ConvertBits(pubKeyBytes, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Encode the data with Bech32 with the prefix "tl1"
	bech32Address, err := bech32.Encode("tl1", data)
	if err != nil {
		return "", err
	}

	return bech32Address, nil
}

func GetBlockchainAddressByUID(app *firebase.App, uid string) (string, error) {
	ctx := context.Background()
	client, err := app.Firestore(ctx)
	if err != nil {
		log.Printf("Failed to get Firestore client: %v", err)
		return "", fmt.Errorf("error getting Firestore client: %v", err)
	}
	defer client.Close()

	doc, err := client.Collection("users").Doc(uid).Get(ctx)
	if err != nil {
		log.Printf("Failed to fetch user document for UID %s: %v", uid, err)
		return "", fmt.Errorf("error fetching user document: %v", err)
	}

	log.Printf("Document data for UID %s: %v", uid, doc.Data()) // Log the document data for debugging

	publicKey, ok := doc.Data()["publicKey"].(string)
	if !ok {
		log.Printf("Public key not found or invalid for user %s", uid)
		return "", fmt.Errorf("public key not found or invalid for user %s", uid)
	}

	return publicKey, nil
}

func (node *Node) GetBlockchainAddressHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := r.URL.Query().Get("userId")
		if uid == "" {
			http.Error(w, "User ID parameter is missing", http.StatusBadRequest)
			return
		}

		blockchainAddress, err := GetBlockchainAddressByUID(node.FirebaseApp, uid)
		if err != nil {
			log.Printf("Failed to retrieve blockchain address for UID %s: %v", uid, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
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
}

func (node *Node) CheckPublicKeyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to serialize response: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
	}
}

func (node *Node) RegisterWalletHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PublicKey string `json:"publicKey"` // Public key expected to be in hex format
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Failed to decode request: %v", err)
			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("Received registration request for public key: %s", req.PublicKey)

		// Decode hex string to bytes
		publicKeyBytes, err := hex.DecodeString(req.PublicKey)
		if err != nil {
			log.Printf("Invalid hex format for public key: %v", err)
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
		initialBalance := int64(70) // Set initial balance for the new wallet
		currentBalance, genesisExists := node.Blockchain.Stakeholders[node.Blockchain.GenesisAccount]
		if !genesisExists || currentBalance < initialBalance {
			http.Error(w, "Insufficient funds in the genesis account.", http.StatusBadRequest)
			return
		}

		// Deduct from genesis and assign to new account
		node.Blockchain.Stakeholders[node.Blockchain.GenesisAccount] -= initialBalance
		node.Blockchain.Stakeholders[bech32Address] = initialBalance

		// Create initial UTXO for the account
		utxo := shared.UTXO{
			OwnerAddress: bech32Address,
			Amount:       initialBalance,
		}
		if err := node.Blockchain.Database.AddUTXO(utxo); err != nil {
			http.Error(w, "Failed to create initial UTXO: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := node.Blockchain.Database.InsertOrUpdateEd25519PublicKey(bech32Address, publicKeyBytes); err != nil {
			http.Error(w, "Failed to save public key to database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Created initial UTXO for %s with amount %d", bech32Address, initialBalance)
		log.Printf("Blockchain address registered and public key saved to database for %s", bech32Address)

		response := struct {
			PublicKey         string `json:"publicKey"`
			BlockchainAddress string `json:"blockchainAddress"`
			Balance           int64  `json:"balance"`
		}{
			PublicKey:         req.PublicKey,
			BlockchainAddress: bech32Address,
			Balance:           initialBalance,
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
}

func (node *Node) GetPublicKeyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			"publicKey": base64.StdEncoding.EncodeToString(publicKey), // Convert the public key to base64
		}

		jsonResp, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to serialize public key response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResp)
	}
}

// Start initializes the HTTP server for the node, setting up endpoints for blockchain, block, peers,
// votes, and transactions handling. It also starts background tasks for discovering peers and counting votes.
func (node *Node) Start() {
	mux := http.NewServeMux() // Create a new ServeMux

	// Define handlers for various endpoints
	mux.HandleFunc("/blockchain", func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(node.Blockchain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	mux.HandleFunc("/get-blockchain-address", node.GetBlockchainAddressHandler())
	mux.HandleFunc("/check-public-key", node.CheckPublicKeyHandler())
	mux.HandleFunc("/get-publickey", node.GetPublicKeyHandler())
	mux.HandleFunc("/register-wallet", node.RegisterWalletHandler())
	mux.HandleFunc("/register-validator", node.RegisterValidatorHandler())
	mux.HandleFunc("/update-stake", node.UpdateStakeHandler())
	mux.HandleFunc("/delegate-stake", node.DelegateStakeHandler())
	mux.HandleFunc("/get-utxo", node.GetUTXOsForAddressHandler())
	mux.HandleFunc("/gas-fee", node.GasEstimateHandler())
	mux.HandleFunc("/get-transaction", node.GetTransactionHandler())

	mux.HandleFunc("/consensus-info", node.ConsensusInfoHandler())

	mux.HandleFunc("/network-health", node.NetworkHealthHandler())

	mux.HandleFunc("/list-transactions-for-block", node.ListTransactionsForBlockHandler())

	mux.HandleFunc("/get-balance", node.GetBalanceHandler())

	mux.HandleFunc("/register-public-key", node.RegisterPublicKeyHandler())

	mux.HandleFunc("/fund-wallet", node.FundWalletHandler())

	mux.HandleFunc("/process-transaction", node.ProcessSignedTransactionHandler())

	mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		var block Block
		if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Retrieving the last block and its index
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
			// If there's an error, respond with an internal server error status and the error message
			http.Error(w, fmt.Sprintf("Failed to add block: %v", err), http.StatusInternalServerError)
			return
		}
		if !success {
			// If the block was not successfully added for some reason (e.g., validation failure),
			// you might want to respond accordingly. Adjust this based on your application's needs.
			http.Error(w, "Failed to add block due to validation or other issues", http.StatusBadRequest)
			return
		}

		// Log the retrieval of the previous block for debugging
		if prevBlock != nil {
			log.Printf("Previous Block Index: %d, Block Hash: %s", prevIndex, prevBlock.Hash)
		} else {
			log.Println("No previous block exists.")
		}

		// If successful, respond with a status indicating the block was created.
		w.WriteHeader(http.StatusCreated)
	})

	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(node.Peers)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	mux.HandleFunc("/vote", func(w http.ResponseWriter, r *http.Request) {
		var vote Vote
		if err := json.NewDecoder(r.Body).Decode(&vote); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		node.Votes = append(node.Votes, vote)
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := node.GetBlockchainStats()
		statsJSON, err := json.Marshal(stats)
		if err != nil {
			http.Error(w, "Failed to serialize blockchain statistics", http.StatusInternalServerError)
			return
		}
		sendResponse(w, statsJSON) // Use your existing sendResponse function to send the JSON data
	})

	mux.HandleFunc("/transaction", func(w http.ResponseWriter, r *http.Request) {
		// Assuming you have a struct that mirrors thrylos.Transaction for JSON purposes
		var jsonTx thrylos.TransactionJSON
		if err := json.NewDecoder(r.Body).Decode(&jsonTx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Convert jsonTx to thrylos.Transaction
		tx := ConvertJSONToProto(jsonTx)

		if err := node.VerifyAndProcessTransaction(tx); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Assuming AddPendingTransaction accepts *thrylos.Transaction
		node.AddPendingTransaction(tx)
		fmt.Printf("Verified and added transaction %s to pending transactions\n", tx.GetId())
		w.WriteHeader(http.StatusCreated)
	})

	// Start background tasks
	tickerDiscoverPeers := time.NewTicker(10 * time.Minute) // Discover peers every 10 minutes
	tickerCountVotes := time.NewTicker(1 * time.Minute)     // Count votes every 1 minute

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

	// Start the HTTP server
	log.Printf("Starting HTTP server on %s", node.Address)
	srv := &http.Server{
		Addr:    node.Address,
		Handler: mux,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start HTTP server on %s: %v", node.Address, err)
	}
}
