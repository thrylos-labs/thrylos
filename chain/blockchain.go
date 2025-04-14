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
	"sync"
	"syscall"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/network"
	"github.com/thrylos-labs/thrylos/store"
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
)

type BlockchainImpl struct {
	Blockchain            *types.Blockchain
	TransactionPropagator *types.TransactionPropagator
	modernProcessor       *processor.ModernProcessor
	txPool                types.TxPool
	dagManager            *processor.DAGManager
	MessageBus            types.MessageBusInterface
}

// Now you can simplify the Close method to use the interface methods
func (bc *BlockchainImpl) Close() error {
	log.Println("Closing blockchain resources...")

	if bc.Blockchain != nil && bc.Blockchain.Database != nil {
		// Get lock file path
		lockFile := bc.Blockchain.Database.GetLockFilePath()
		if lockFile != "" {
			log.Printf("Lock file path: %s", lockFile)
		}

		// Close the database
		if err := bc.Blockchain.Database.Close(); err != nil {
			return fmt.Errorf("error closing database: %v", err)
		}
		log.Println("Database closed successfully")
	}

	log.Println("Blockchain resources closed successfully")
	return nil
}

func NewBlockchain(config *types.BlockchainConfig) (*BlockchainImpl, types.Store, error) {
	// Initialize the database
	database, err := store.NewDatabase(config.DataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
	}

	storeInstance, err := store.NewStore(database, config.AESKey)
	if err != nil {
		database.Close()
		return nil, nil, fmt.Errorf("failed to create store: %v", err)
	}

	database.Blockchain = storeInstance
	log.Println("BlockchainDB created")

	genesis := NewGenesisBlock()
	log.Println("Genesis block created")
	publicKeyMap := make(map[string]*crypto.PublicKey)
	totalSupplyNano := int64(120000000 * 1e9) // 120M THRYLOS in nanoTHRYLOS
	log.Printf("Initializing genesis account with total supply: %.2f THR", float64(totalSupplyNano)/1e9)

	stakeholdersMap := make(map[string]int64)
	privKey, err := crypto.NewPrivateKey()
	if err != nil {
		log.Printf("error generating private key for genesis account: %v", err)
		return nil, nil, err
	}
	var pubKey crypto.PublicKey = privKey.PublicKey() // Declare as variable
	addr, _ := pubKey.Address()
	stakeholdersMap[addr.String()] = totalSupplyNano
	log.Printf("Genesis account address: %s", addr.String())

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

	utxoMap := make(map[string][]*thrylos.UTXO)
	utxoKey := fmt.Sprintf("%s:%d", genesisTx.Id, 0)
	utxoMap[utxoKey] = []*thrylos.UTXO{genesisTx.Outputs[0]}

	genesis.Transactions = []*types.Transaction{utils.ConvertToSharedTransaction(genesisTx)}

	stateNetwork := network.NewDefaultNetwork()
	messageBus := types.GetGlobalMessageBus()
	temp := &BlockchainImpl{
		Blockchain: &types.Blockchain{
			Blocks:              []*types.Block{genesis},
			Genesis:             genesis,
			Stakeholders:        stakeholdersMap,
			Database:            storeInstance,
			PublicKeyMap:        publicKeyMap,
			UTXOs:               utxoMap,
			Forks:               make([]*types.Fork, 0),
			GenesisAccount:      privKey,
			PendingTransactions: make([]*thrylos.Transaction, 0),
			ActiveValidators:    make([]string, 0),
			StateNetwork:        stateNetwork,
			TestMode:            config.TestMode,
		},
		MessageBus: messageBus,
	}

	temp.TransactionPropagator = &types.TransactionPropagator{
		Blockchain: temp,
		Mu:         sync.RWMutex{},
	}
	temp.txPool = NewTxPool(database, temp)

	// Subscribe to FundNewAddress using BlockchainImpl's MessageBus
	ch := make(chan types.Message, 100)
	temp.MessageBus.Subscribe(types.FundNewAddress, ch)
	go func() {
		log.Println("Started FundNewAddress message listener")
		for msg := range ch {
			log.Printf("Received message: %s", msg.Type)
			if msg.Type == types.FundNewAddress {
				temp.HandleFundNewAddress(msg)
			}
		}
	}()

	// In your NewBlockchain function, add this after the other subscriptions:
	balanceCh := make(chan types.Message, 100)
	temp.MessageBus.Subscribe(types.GetStakeholderBalance, balanceCh)
	go func() {
		log.Println("Started GetStakeholderBalance message listener")
		for msg := range balanceCh {
			log.Printf("Received balance message: %s", msg.Type)
			if msg.Type == types.GetStakeholderBalance {
				temp.HandleGetBalance(msg)
			}
		}
	}()

	publicKeyMap[addr.String()] = &pubKey
	log.Println("Genesis account public key added to publicKeyMap")

	if err := database.Blockchain.SaveBlock(genesis); err != nil {
		return nil, nil, fmt.Errorf("failed to add genesis block to the database: %v", err)
	}

	log.Printf("Genesis account %s initialized with total supply: %d nanoTHRYLOS", addr.String(), totalSupplyNano)

	if err := database.Blockchain.SaveBlock(genesis); err != nil {
		return nil, nil, fmt.Errorf("failed to add genesis block to the database: %v", err)
	}

	log.Printf("Genesis account %s initialized with total supply: %d nanoTHRYLOS", addr.String(), totalSupplyNano)
	// Shutdown handler
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Stopping blockchain...")
	}()

	if !config.DisableBackground {
		go func() {
			log.Println("Starting block creation process")
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				txs, err := temp.txPool.GetAllTransactions()
				if err != nil {
					log.Printf("Error getting transactions from pool: %v", err)
					continue
				}
				if len(txs) > 0 {
					log.Printf("Processing %d transactions from pool", len(txs))
					for _, tx := range txs {
						if err := temp.ProcessIncomingTransaction(tx); err != nil {
							log.Printf("Error processing transaction: %v", err)
						}
					}
				}
			}
		}()
	} else {
		log.Println("Background processes disabled for testing")
	}

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

func (bc *BlockchainImpl) HandleGetBalance(msg types.Message) {
	address, ok := msg.Data.(string)
	if !ok {
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid address format")}
		return
	}

	log.Printf("DEBUG-BALANCE: HandleGetBalance called for address: %s", address)

	// Access the stakeholders map
	bc.Blockchain.Mu.RLock()

	// Direct map access check
	mapSize := len(bc.Blockchain.Stakeholders)
	log.Printf("DEBUG-BALANCE: Stakeholders map has %d entries", mapSize)

	// Check for specific addresses
	genesis, _ := bc.Blockchain.GenesisAccount.PublicKey().Address()
	genesisAddr := genesis.String()
	genesisBalance, genesisExists := bc.Blockchain.Stakeholders[genesisAddr]
	log.Printf("DEBUG-BALANCE: Genesis address %s exists: %v, balance: %d",
		genesisAddr, genesisExists, genesisBalance)

	testBalance, testExists := bc.Blockchain.Stakeholders["test_address_123"]
	log.Printf("DEBUG-BALANCE: Test address exists: %v, balance: %d", testExists, testBalance)

	// Check the target address
	targetBalance, targetExists := bc.Blockchain.Stakeholders[address]
	log.Printf("DEBUG-BALANCE: Target address %s exists: %v, balance: %d",
		address, targetExists, targetBalance)

	// Print all entries in the map
	log.Printf("DEBUG-BALANCE: All addresses in map:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}

	// Get the final balance
	balance := int64(0)
	if targetExists {
		balance = targetBalance
		log.Printf("DEBUG-BALANCE: Using balance %d from map", balance)
	} else {
		log.Printf("DEBUG-BALANCE: No balance found, using 0")
	}

	bc.Blockchain.Mu.RUnlock()

	// Send the response
	log.Printf("DEBUG-BALANCE: Sending final balance: %d", balance)
	msg.ResponseCh <- types.Response{Data: balance}
}

func (bc *BlockchainImpl) TestStakeholdersMap() {
	testAddress := "test_address_123"

	// Print initial state
	bc.Blockchain.Mu.RLock()
	log.Printf("TEST: Initial stakeholders map:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}
	initialBalance, exists := bc.Blockchain.Stakeholders[testAddress]
	bc.Blockchain.Mu.RUnlock()

	log.Printf("TEST: Initial balance for %s: %d (exists: %v)", testAddress, initialBalance, exists)

	// Modify the map
	bc.Blockchain.Mu.Lock()
	bc.Blockchain.Stakeholders[testAddress] = 12345
	bc.Blockchain.Mu.Unlock()

	// Check if the modification worked
	bc.Blockchain.Mu.RLock()
	newBalance, exists := bc.Blockchain.Stakeholders[testAddress]
	bc.Blockchain.Mu.RUnlock()

	log.Printf("TEST: After modification, balance for %s: %d (exists: %v)", testAddress, newBalance, exists)

	// Print final state
	bc.Blockchain.Mu.RLock()
	log.Printf("TEST: Final stakeholders map:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}
	bc.Blockchain.Mu.RUnlock()
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

// TO DO FIND WHERE VerifyTransaction IS AND SimulateValidatorSigning
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
	// Update UTXO set
	for _, tx := range signedBlock.Transactions {
		// Remove spent UTXOs
		for _, input := range tx.Inputs {
			utxoKey := fmt.Sprintf("%s:%d", input.ID, input.Index)
			delete(bc.Blockchain.UTXOs, utxoKey)
		}
		// Add new UTXOs
		for index, output := range tx.Outputs {
			utxoKey := fmt.Sprintf("%s:%d", tx.ID, index)
			// Convert the types.UTXO to thrylos.UTXO with correct protobuf fields
			thrylosUTXO := &thrylos.UTXO{
				TransactionId: tx.ID,
				Index:         int32(index),
				OwnerAddress:  output.OwnerAddress,
				Amount:        int64(output.Amount), // Cast amount.Amount to int64
				IsSpent:       false,
			}
			bc.Blockchain.UTXOs[utxoKey] = []*thrylos.UTXO{thrylosUTXO}
		}
	}

	// Serialize and store the block
	blockData, err := json.Marshal(signedBlock)
	if err != nil {
		return false, fmt.Errorf("failed to serialize new block: %v", err)
	}

	blockNumber := len(bc.Blockchain.Blocks)
	if err := bc.Blockchain.Database.StoreBlock(blockData, blockNumber); err != nil {
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
