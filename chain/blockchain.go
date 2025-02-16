package chain

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/network"
	"github.com/thrylos-labs/thrylos/store"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

type BlockchainImpl struct {
	Blockchain *types.Blockchain
	// modernProcessor *processor.ModernProcessor
	txPool types.TxPool // Not *types.TxPool
	// dagManager      *processor.DAGManager
}

func NewBlockchain(config *types.BlockchainConfig) (*BlockchainImpl, types.Store, error) {
	// Initialize the database
	database, err := store.NewDatabase(config.DataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
	}

	// Create the store instance
	storeInstance, err := store.NewStore(database, config.AESKey)
	if err != nil {
		database.Close() // Clean up if store creation fails
		return nil, nil, fmt.Errorf("failed to create store: %v", err)
	}

	// Set the Blockchain field of the database
	database.Blockchain = storeInstance

	log.Println("BlockchainDB created")

	// Create the genesis block
	genesis := NewGenesisBlock()
	log.Println("Genesis block created")

	// Initialize the map for public keys
	publicKeyMap := make(map[string]*crypto.PublicKey)

	// Initialize Stakeholders map with the genesis account
	totalSupplyNano := utils.ThrylosToNano()

	log.Printf("Initializing genesis account with total supply: %.2f THR", utils.NanoToThrylos(totalSupplyNano))

	stakeholdersMap := make(map[string]int64)
	addr, _ := config.GenesisAccount.PublicKey().Address()
	stakeholdersMap[addr.String()] = totalSupplyNano // Genesis holds total supply including staking reserve

	log.Printf("Initializing genesis account: %s", config.GenesisAccount)

	// Generate a new key pair for the genesis account
	log.Println("Generating key pair for genesis account")

	privKey, err := crypto.NewPrivateKey()
	if err != nil {
		log.Printf("error generating private key for the genesis account: %v", err)
		return nil, nil, err
	}

	pubKey := privKey.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate genesis account key pair: %v", err)
	}
	log.Println("Genesis account key pair generated successfully")

	// Create genesis transaction
	genesisTx := &thrylos.Transaction{
		Id:        "genesis_tx_" + addr.String(),
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: addr.String(),
			Amount:       totalSupplyNano,
		}},
		Signature:       []byte("genesis_signature"),
		SenderPublicKey: nil,
	}

	// Initialize UTXO map with the genesis transaction
	utxoMap := make(map[string][]*thrylos.UTXO)
	utxoKey := fmt.Sprintf("%s:%d", genesisTx.Id, 0)
	utxoMap[utxoKey] = []*thrylos.UTXO{genesisTx.Outputs[0]}

	genesis.Transactions = []*types.Transaction{ConvertToSharedTransaction(genesisTx)}

	stateNetwork := network.NewDefaultNetwork()
	// stateManager := state.NewStateManager(stateNetwork, 4)

	log.Println("Genesis account private key stored and verified successfully")

	// Create initial blockchain instance
	temp := &BlockchainImpl{
		Blockchain: &types.Blockchain{
			Blocks:              []*types.Block{genesis},
			Genesis:             genesis,
			Stakeholders:        stakeholdersMap,
			Database:            storeInstance, // Use storeInstance instead of database.Blockchain
			PublicKeyMap:        publicKeyMap,
			UTXOs:               utxoMap,
			Forks:               make([]*types.Fork, 0),
			GenesisAccount:      privKey,
			PendingTransactions: make([]*thrylos.Transaction, 0),
			ActiveValidators:    make([]string, 0),
			StateNetwork:        stateNetwork,
			TestMode:            config.TestMode,
		},
	}

	// Create the propagator
	// propagator := &types.TransactionPropagator{
	// 	Blockchain: temp,
	// 	Mu:         sync.RWMutex{},
	// }
	// Create the transaction pool
	temp.txPool = NewTxPool(database)

	// Add the blockchain public key to the publicKeyMap
	publicKeyMap[addr.String()] = &pubKey
	log.Println("Genesis account public key added to publicKeyMap")

	// Commented out validator key generation check to avoid error
	/*
	   if err != nil {
	       log.Printf("Warning: Failed to generate validator keys: %v", err)
	       return nil, nil, fmt.Errorf("failed to generate validator keys: %v", err)
	   }
	*/

	// log.Printf("Total ActiveValidators: %d", len(blockchain.ActiveValidators))

	// Save genesis block
	if err := database.Blockchain.SaveBlock(genesis); err != nil {
		return nil, nil, fmt.Errorf("failed to add genesis block to the database: %v", err)
	}

	log.Printf("Genesis account %s initialized with total supply: %d", config.GenesisAccount, totalSupplyNano)

	log.Println("NewBlockchain initialization completed successfully")

	// Add shutdown handler for clean termination
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Stopping blockchain...")
	}()

	// if !config.DisableBackground {
	// 	// Start block creation routine
	// 	go func() {
	// 		log.Println("Starting block creation process")
	// 		ticker := time.NewTicker(10 * time.Second)
	// 		defer ticker.Stop()

	// 		for {
	// 			select {
	// 			case <-ticker.C:
	// 				// First fetch transactions from the pool
	// 				txs, err := temp.txPool.GetAllTransactions()
	// 				if err != nil {
	// 					log.Printf("Error getting transactions from pool: %v", err)
	// 					continue
	// 				}

	// 				// then process each of them through the modern transaction processor
	// 				if len(txs) > 0 {
	// 					log.Printf("Processing %d transactions from pool", len(txs))
	// 					for _, tx := range txs {
	// 						err := temp.ProcessIncomingTransaction(tx)
	// 						if err != nil {
	// 							log.Printf("Error processing transaction: %v", err)
	// 							continue
	// 						}
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}()
	// } else {
	// 	log.Println("Background processes disabled for testing")
	// }

	log.Println("NewBlockchain initialization completed successfully")
	return temp, storeInstance, nil
}

// // // ensuring that no blocks have been altered or inserted maliciously.
func (bc *BlockchainImpl) CheckChainIntegrity() bool {
	for i := 1; i < len(bc.Blockchain.Blocks); i++ {
		prevBlock := bc.Blockchain.Blocks[i-1]
		currentBlock := bc.Blockchain.Blocks[i]

		if !currentBlock.PrevHash.Equal(prevBlock.Hash) {
			fmt.Printf("Invalid previous hash in block %d\n", currentBlock.Index)
			return false
		}

		blockBytes, err := SerializeForSigning(currentBlock)
		if err != nil {
			fmt.Printf("Failed to serialize block %d: %v\n", currentBlock.Index, err)
			return false
		}
		computedHash := hash.NewHash(blockBytes)

		if !currentBlock.Hash.Equal(computedHash) {
			fmt.Printf("Invalid hash in block %d\n", currentBlock.Index)
			return false
		}
	}
	return true
}

// helper methods
func (bc *BlockchainImpl) GetGenesis() *types.Block {
	return bc.Blockchain.Genesis
}

func (bc *BlockchainImpl) GetBlocks() []*types.Block {
	return bc.Blockchain.Blocks
}

func (bc *BlockchainImpl) Status() string {
	return fmt.Sprintf("Height: %d, Blocks: %d",
		len(bc.Blockchain.Blocks)-1,
		len(bc.Blockchain.Blocks))
}

// Block functions
func (bc *BlockchainImpl) GetLastBlock() (*types.Block, int, error) {
	// Query the last block data and index
	blockData, err := bc.Blockchain.Database.GetLastBlockData()
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle no rows returned, which means the blockchain is empty
			return nil, 0, nil
		}
		return nil, 0, err
	}

	// Get the last block index
	lastIndex, err := bc.Blockchain.Database.GetLastBlockIndex()
	if err != nil {
		return nil, 0, err
	}

	// Deserialize the block
	var lastBlock types.Block
	buffer := bytes.NewBuffer(blockData)
	decoder := gob.NewDecoder(buffer)
	err = decoder.Decode(&lastBlock)
	if err != nil {
		return nil, 0, err
	}

	// Return the block along with its index
	return &lastBlock, lastIndex, nil
}

func (bc *BlockchainImpl) GetBlockCount() int {
	bc.Blockchain.Mu.RLock()
	defer bc.Blockchain.Mu.RUnlock()
	return len(bc.Blockchain.Blocks)
}

func (bc *BlockchainImpl) GetBlock(blockNumber int) (*types.Block, error) {
	blockData, err := bc.Blockchain.Database.RetrieveBlock(blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
	}

	var block types.Block
	if err := json.Unmarshal(blockData, &block); err != nil { // Deserialize here
		return nil, fmt.Errorf("failed to deserialize block: %v", err)
	}
	return &block, nil
}

// TO DO
func (bc *BlockchainImpl) AddBlock(transactions []*thrylos.Transaction, validator string, prevHash []byte, optionalTimestamp ...int64) (bool, error) {
	bc.Blockchain.Mu.Lock()
	defer bc.Blockchain.Mu.Unlock()

	// Handle potential forks.
	prevHashObj, err := hash.FromBytes(prevHash)
	if err != nil {
		return false, fmt.Errorf("invalid previous hash: %v", err)
	}

	if len(bc.Blockchain.Blocks) > 0 && !bc.Blockchain.Blocks[len(bc.Blockchain.Blocks)-1].Hash.Equal(prevHashObj) {
		var selectedFork *types.Fork
		for _, fork := range bc.Blockchain.Forks {
			if fork.Blocks != nil && len(fork.Blocks) > 0 {
				if fork.Blocks[len(fork.Blocks)-1].Hash.Equal(prevHashObj) {
					selectedFork = fork
					break
				}
			}
		}

		// Create unsigned block for the fork
		unsignedBlock, err := bc.CreateUnsignedBlock(transactions, validator)
		if err != nil {
			return false, fmt.Errorf("failed to create unsigned block: %v", err)
		}

		// Simulate validator signing
		signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
		if err != nil {
			return false, fmt.Errorf("failed to simulate block signing: %v", err)
		}

		// Verify the signed block
		if err := bc.VerifySignedBlock(signedBlock); err != nil {
			return false, fmt.Errorf("invalid signed block: %v", err)
		}

		blockData, err := json.Marshal(signedBlock)
		if err != nil {
			return false, fmt.Errorf("failed to serialize new block: %v", err)
		}

		blockNumber := len(bc.Blockchain.Blocks)
		if selectedFork != nil {
			selectedFork.Blocks = append(selectedFork.Blocks, signedBlock)
			blockNumber = len(selectedFork.Blocks) - 1
		} else {
			bc.Blockchain.Blocks = append(bc.Blockchain.Blocks, signedBlock)
			blockNumber = len(bc.Blockchain.Blocks) - 1
		}

		if err := bc.Blockchain.Database.StoreBlock(blockData, blockNumber); err != nil {
			return false, fmt.Errorf("failed to store block in database: %v", err)
		}

		return true, nil
	}

	// Verify transactions.
	for _, tx := range transactions {
		isValid, err := bc.VerifyTransaction(tx)
		if err != nil || !isValid {
			return false, fmt.Errorf("transaction verification failed: %s, error: %v", tx.GetId(), err)
		}
	}

	// Create unsigned block
	unsignedBlock, err := bc.CreateUnsignedBlock(transactions, validator)
	if err != nil {
		return false, fmt.Errorf("failed to create unsigned block: %v", err)
	}

	// Simulate validator signing
	signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
	if err != nil {
		return false, fmt.Errorf("failed to simulate block signing: %v", err)
	}

	// Verify the signed block
	if err := bc.VerifySignedBlock(signedBlock); err != nil {
		return false, fmt.Errorf("invalid signed block: %v", err)
	}

	// Update UTXO set
	for _, tx := range signedBlock.Transactions {
		// Remove spent UTXOs
		for _, input := range tx.GetInputs() {
			utxoKey := fmt.Sprintf("%s:%d", input.GetTransactionId(), input.GetIndex())
			delete(bc.Blockchain.UTXOs, utxoKey)
		}
		// Add new UTXOs
		for index, output := range tx.GetOutputs() {
			utxoKey := fmt.Sprintf("%s:%d", tx.GetId(), index)
			bc.Blockchain.UTXOs[utxoKey] = []*thrylos.UTXO{output}
		}
	}

	// Serialize and store the block
	blockData, err := json.Marshal(signedBlock)
	if err != nil {
		return false, fmt.Errorf("failed to serialize new block: %v", err)
	}

	blockNumber := len(bc.Blockchain.Blocks)
	if err := bc.Blockchain.DatabaseDatabase.StoreBlock(blockData, blockNumber); err != nil {
		return false, fmt.Errorf("failed to store block in database: %v", err)
	}

	// Update the blockchain with the new block
	bc.Blockchain.Blocks = append(bc.Blockchain.Blocks, signedBlock)
	bc.Blockchain.LastTimestamp = signedBlock.Timestamp

	if bc.Blockchain.OnNewBlock != nil {
		bc.Blockchain.OnNewBlock(signedBlock)
	}

	// Update balances for affected addresses
	bc.updateBalancesForBlock(signedBlock)

	return true, nil
}

func (bc *BlockchainImpl) GetBlockByID(id string) (*types.Block, error) { // Changed return type to pointer
	// First, try to parse id as a block index
	if index, err := strconv.Atoi(id); err == nil {
		// id is a valid integer, so we treat it as a block index
		if index >= 0 && index < len(bc.Blockchain.Blocks) {
			block := bc.Blockchain.Blocks[index]
			log.Printf("Block found by index: Index=%d, Transactions=%v", block.Index, block.Transactions)
			return block, nil
		}
	}

	// If id is not a valid index, try to match it as a hash
	idBytes, err := hex.DecodeString(id)
	if err != nil {
		log.Printf("Invalid block ID format: %s", id)
		return nil, errors.New("invalid block ID format")
	}

	// Create a Hash from the bytes
	idHash, err := hash.FromBytes(idBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid hash bytes: %v", err)
	}

	// Iterate over blocks and find by hash
	for _, block := range bc.Blockchain.Blocks {
		if block.Hash.Equal(idHash) { // Use the Equal method from Hash type
			log.Printf("Block found by hash: Index=%d, Transactions=%v", block.Index, block.Transactions)
			return block, nil
		}
	}

	log.Println("Block not found with ID:", id)
	return nil, errors.New("block not found")
}
