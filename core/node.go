package core

import (
	thrylos "Thrylos"
	"Thrylos/shared"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Vote represents a vote cast by a validator for a specific block. It includes the block hash being voted for,
// the validator's address, and the stake the validator had at the time of voting. This is used in consensus mechanisms
// that involve staking and voting for block validity.
type Vote struct {
	BlockHash string // Hash of the block that is being voted for.
	Validator string // Address of the validator casting the vote.
	Stake     int    // Stake amount of the validator at the time of voting.
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

}

// NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// blockchain instance for the node and optionally discovers peers if not running in a test environment.
func NewNode(address string, knownPeers []string, shard *Shard, isTest bool) *Node {
	bc, err := NewBlockchain()
	if err != nil {
		log.Fatalf("Failed to create new blockchain: %v", err)
	}

	node := &Node{
		Address:      address,
		Peers:        knownPeers,
		Blockchain:   bc,
		Shard:        shard,
		PublicKeyMap: make(map[string]ed25519.PublicKey), // Initialize the map
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

	// Assuming your Blockchain has a method GetUTXOsForAddress that returns all UTXOs for a given address.
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

// CreateAndBroadcastTransaction creates a new transaction with the specified recipient and amount,
// signs it with the sender's Ed25519 private key, and broadcasts it to the network.
func (node *Node) CreateAndBroadcastTransaction(recipientAddress string, amount int, privateKey ed25519.PrivateKey) error {
	// Attempt to gather inputs for the transaction along with change and potential error
	inputs, change, err := node.CollectInputsForTransaction(amount, node.Address)
	if err != nil {
		return fmt.Errorf("failed to collect inputs for transaction: %v", err)
	}

	// Prepare outputs for the transaction
	outputs := []shared.UTXO{{OwnerAddress: recipientAddress, Amount: amount}}
	// If there's change, add a new UTXO to outputs for the sender's change
	if change > 0 {
		outputs = append(outputs, shared.UTXO{OwnerAddress: node.Address, Amount: change})
	}

	// Create and sign the transaction using Ed25519
	transaction, err := shared.CreateAndSignTransaction("txID", inputs, outputs, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create and sign transaction: %v", err)
	}

	// Broadcast the transaction to the network
	node.BroadcastTransaction(&transaction)
	return nil
}

func (node *Node) RetrievePublicKey(address string) (ed25519.PublicKey, error) {
	pubKey, exists := node.PublicKeyMap[address]
	if !exists {
		return nil, fmt.Errorf("public key not found for address: %s", address)
	}
	return pubKey, nil
}

func (node *Node) StorePublicKey(address string, publicKey ed25519.PublicKey) {
	node.PublicKeyMap[address] = publicKey
}

// VerifyAndProcessTransaction verifies the transaction's signature using Ed25519 and processes it if valid.
func (node *Node) VerifyAndProcessTransaction(tx *thrylos.Transaction) error {
	// Retrieve the sender's public key as an Ed25519 public key
	senderPublicKey, err := node.RetrievePublicKey(tx.Inputs[0].OwnerAddress) // Ensure this returns ed25519.PublicKey
	if err != nil {
		return fmt.Errorf("failed to retrieve public key: %v", err)
	}

	// Verify the transaction signature with Ed25519 public key
	if err := shared.VerifyTransactionSignature(tx, senderPublicKey); err != nil {
		return fmt.Errorf("transaction signature verification failed: %v", err)
	}

	// Process the transaction...
	return nil
}

func sendResponse(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// SubmitTransactionHandler processes transaction submissions to the node.
func (node *Node) SubmitTransactionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tx thrylos.Transaction
		err := json.NewDecoder(r.Body).Decode(&tx)
		if err != nil {
			http.Error(w, "Invalid transaction format", http.StatusBadRequest)
			return
		}

		// Add transaction to pending transactions
		err = node.AddPendingTransaction(&tx)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to add transaction: %v", err), http.StatusInternalServerError)
			return
		}

		// Optionally, broadcast transaction to peers here...

		// Respond with success
		// w.WriteHeader(http.StatusAccepted)
		// fmt.Fprintf(w, "Transaction submitted successfully")
		sendResponse(w, []byte("Transaction submitted successfully"))
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

		blockJSON, err := json.Marshal(block)
		if err != nil {
			http.Error(w, "Failed to serialize block", http.StatusInternalServerError)
			return
		}

		sendResponse(w, blockJSON)
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

// TotalStake calculates the total amount of stake from all stakeholders in the blockchain. This is used
// in consensus mechanisms that involve staking.
func (bc *Blockchain) TotalStake() int {
	var total int
	for _, stake := range bc.Stakeholders {
		total += stake
	}
	return total
}

// CountVotes tallies the votes for blocks from validators and updates the blockchain accordingly. It plays
// a crucial role in consensus mechanisms where blocks are accepted based on validator votes.
func (node *Node) CountVotes() {
	majorityStake := node.Blockchain.TotalStake()/2 + 1
	voteStakes := make(map[string]int)

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

const minStakeRequirement = 1000 // This represents the minimum amount of stake required to become a validator.

func (bc *Blockchain) SelectValidator() string {
	var totalStake int

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
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Non-OK HTTP status from peer:", resp.StatusCode)
			continue
		}

		var peerBlockchain Blockchain
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&peerBlockchain)
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
		Signature: jsonTx.Signature,
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

	mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		var block Block
		if err := json.NewDecoder(r.Body).Decode(&block); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		prevBlock, err := node.Blockchain.GetLastBlock()
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
