package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"

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
// the blockchain, a list of peers, a shard reference, and a pool of pending transactions to be included in future blocks.
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

	// Assuming you have a way to get or set a default genesis account address
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")
	if genesisAccount == "" {
		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
	}

	bc, err := NewBlockchain(dataDir, aesKey, genesisAccount) // Pass both dataDir and aesKey to the NewBlockchain function
	if err != nil {
		log.Fatalf("Failed to create new blockchain: %v", err)
	}

	node := &Node{
		Address:          address,
		Peers:            knownPeers,
		Blockchain:       bc,
		Shard:            shard,
		PublicKeyMap:     make(map[string]ed25519.PublicKey), // Initialize the map
		ResponsibleUTXOs: make(map[string]shared.UTXO),
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

func (node *Node) CollectInputsForTransaction(amount int, senderAddress string) (inputs []shared.UTXO, change int, err error) {
	var collectedAmount int
	var collectedInputs []shared.UTXO

	utxos := node.Blockchain.GetUTXOsForAddress(senderAddress)
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
func (node *Node) CreateAndBroadcastTransaction(recipientAddress string, from *string, amount int, data *[]byte, gas *int) error {
	// Retrieve the private key securely
	var ed25519PrivateKey ed25519.PrivateKey

	var aesKey []byte
	if data != nil {
		aesKey = *data
	}

	// Calculate gas based on data size if not provided
	var gasFee int
	if gas != nil {
		gasFee = *gas
	} else if data != nil {
		gasFee = CalculateGas(len(*data))
	} else {
		gasFee = CalculateGas(0) // Default base fee if no data is present
	}

	// Total amount includes the gas fee
	totalAmount := amount + gasFee

	inputs, change, err := node.CollectInputsForTransaction(totalAmount, node.Address)
	if err != nil {
		return fmt.Errorf("failed to collect inputs for transaction: %v", err)
	}

	outputs := []shared.UTXO{{OwnerAddress: recipientAddress, Amount: amount}}
	if change > 0 {
		outputs = append(outputs, shared.UTXO{OwnerAddress: node.Address, Amount: change})
	}

	// Generate a unique transaction ID
	// Generate a unique transaction ID
	transactionID, err := shared.GenerateTransactionID(inputs, outputs, node.Address, amount, gasFee)
	if err != nil {
		// Handle the error appropriately, perhaps by returning it or logging it
		return fmt.Errorf("failed to generate transaction ID: %v", err)
	}

	transaction, err := shared.CreateAndSignTransaction(transactionID, node.Address, inputs, outputs, ed25519PrivateKey, aesKey)
	if err != nil {
		return fmt.Errorf("failed to create and sign transaction: %v", err)
	}

	node.BroadcastTransaction(transaction)
	return nil
}

func (node *Node) GetTransactionReceipt(txHash string) (map[string]interface{}, error) {
	// This method should return the transaction receipt for a given transaction hash.
	// A mock receipt is returned for demonstration purposes.
	return map[string]interface{}{
		"transactionHash": txHash,
		"status":          "success",
		"blockNumber":     "0x1A4",  // Hexadecimal value of the block number
		"gasUsed":         "0x5208", // Hexadecimal value of the gas used
	}, nil
}

func (node *Node) RetrievePublicKey(address string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	pubKey, exists := node.PublicKeyMap[address]
	if !exists {
		// Enhanced error logging
		errorMsg := fmt.Sprintf("public key not found for address: %s", address)
		log.Printf(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}
	// Display the public key in hexadecimal format for detailed verification
	log.Printf("Public key retrieved: %x for address: %s", pubKey, address)
	return pubKey, nil
}

func (node *Node) StorePublicKey(address string, publicKey ed25519.PublicKey) {
	node.PublicKeyMap[address] = publicKey
}

// VerifyAndProcessTransaction verifies the transaction's signature using Ed25519 and processes it if valid.
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
	return &shared.Transaction{
		ID:            tx.GetId(),
		Timestamp:     tx.GetTimestamp(),
		Inputs:        ConvertProtoInputs(tx.GetInputs()),
		Outputs:       ConvertProtoOutputs(tx.GetOutputs()),
		Signature:     tx.GetSignature(), // Convert []byte to string here
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
				Amount:        int(input.GetAmount()), // Corrected type conversion
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
				Amount:        int(output.GetAmount()), // Corrected type conversion
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

func (node *Node) CreateWalletHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate public and private keys along with a mnemonic for recovery
		publicKey, _, mnemonic, err := shared.GenerateEd25519Keys()
		if err != nil {
			http.Error(w, "Failed to generate wallet: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Convert publicKey to hexadecimal string
		publicKeyHex := hex.EncodeToString(publicKey)

		// Prepare the wallet response; do not send the private key over the network
		wallet := struct {
			Mnemonic  string `json:"mnemonic"`  // Seed phrase for wallet recovery
			PublicKey string `json:"publicKey"` // Public key to be shared
		}{
			Mnemonic:  mnemonic,
			PublicKey: publicKeyHex, // Use the hex string of the public key
		}

		response, err := json.Marshal(wallet)
		if err != nil {
			http.Error(w, "Failed to serialize wallet data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
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

func (node *Node) SubmitTransactionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Decode the incoming JSON to the Transaction struct
		var tx shared.Transaction
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&tx); err != nil {
			log.Printf("Error decoding transaction: %v", err)
			http.Error(w, "Invalid transaction format", http.StatusBadRequest)
			return
		}

		log.Printf("Received transaction request: %+v", tx)

		// Validate the transaction
		if err := tx.Validate(); err != nil {
			log.Printf("Validation failed for transaction: %v, Error: %v", tx, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Convert local Transaction type to thrylos.Transaction if needed
		thrylosTx, err := shared.ConvertLocalTransactionToThrylosTransaction(tx)
		if err != nil {
			log.Printf("Error converting to thrylos.Transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Verify and process the transaction
		if err := node.VerifyAndProcessTransaction(thrylosTx); err != nil {
			log.Printf("Invalid transaction: %v, Transaction: %+v", err, thrylosTx)
			http.Error(w, fmt.Sprintf("Invalid transaction: %v", err), http.StatusUnprocessableEntity)
			return
		}

		// Add transaction to pending transactions
		if err := node.AddPendingTransaction(thrylosTx); err != nil {
			log.Printf("Failed to add transaction to pending transactions: %v", err)
			http.Error(w, fmt.Sprintf("Failed to add transaction: %v", err), http.StatusInternalServerError)
			return
		}

		log.Println("Transaction submitted and broadcasted successfully")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Transaction submitted successfully"))
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
		address := r.URL.Query().Get("address")
		if address == "" {
			response := `{"error":"Address parameter is missing"}`
			log.Println("Sending error response:", response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(response))
			return
		}

		balance, err := node.Blockchain.GetBalance(address)
		if err != nil {
			response := fmt.Sprintf(`{"error":"Failed to get balance for address %s: %v"}`, address, err)
			log.Println("Sending error response:", response)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(response))
			return
		}

		response := map[string]interface{}{
			"address": address,
			"balance": balance,
		}
		w.Header().Set("Content-Type", "application/json")
		jsonResp, _ := json.Marshal(response)
		log.Printf("Sending success response: %s\n", jsonResp) // Log the response
		w.Write(jsonResp)
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
func (node *Node) BroadcastTransaction(tx *shared.Transaction) {
	txData, err := json.Marshal(tx)
	if err != nil {
		fmt.Println("Failed to serialize transaction:", err)
		return
	}

	// Iterate through the list of peer addresses and send the transaction to each.
	for _, peer := range node.Peers {
		url := fmt.Sprintf("http://%s/transaction", peer) // Use HTTP for now
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(txData))
		if err != nil {
			fmt.Println("Failed to post transaction to peer:", err)
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			fmt.Println("Received non-OK response when broadcasting transaction to peer:", resp.Status)
		}
		resp.Body.Close() // Ensure the response body is closed after handling
	}
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

// FundWalletHandler transfers a predefined amount from the genesis account to a new user's wallet.
func (node *Node) FundWalletHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Log raw body for debugging
		bodyBytes, _ := ioutil.ReadAll(r.Body)
		fmt.Println("Received body:", string(bodyBytes))

		// Rewind the request body for JSON decoding
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		var request struct {
			Address string `json:"address"` // User's wallet address
			Amount  int64  `json:"amount"`  // Ensure to include amount if it's dynamic
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Transfer funds from the genesis account
		err := node.Blockchain.TransferFunds("", request.Address, request.Amount)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fund wallet: %v", err), http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"message": fmt.Sprintf("Funded wallet with %d successfully", request.Amount),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
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

	mux.HandleFunc("/register-validator", node.RegisterValidatorHandler())
	mux.HandleFunc("/update-stake", node.UpdateStakeHandler())
	mux.HandleFunc("/delegate-stake", node.DelegateStakeHandler())

	mux.HandleFunc("/consensus-info", node.ConsensusInfoHandler())

	mux.HandleFunc("/network-health", node.NetworkHealthHandler())

	mux.HandleFunc("/list-transactions-for-block", node.ListTransactionsForBlockHandler())

	mux.HandleFunc("/create-wallet", node.CreateWalletHandler())

	mux.HandleFunc("/get-balance", node.GetBalanceHandler())

	mux.HandleFunc("/register-public-key", node.RegisterPublicKeyHandler())

	mux.HandleFunc("/fund-wallet", node.FundWalletHandler())

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
