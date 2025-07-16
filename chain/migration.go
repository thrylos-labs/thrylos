package chain

import (
	"fmt"
	"log"
)

// Add these methods to your BlockchainImpl

// GetTotalNumShards returns the total number of shards
func (bc *BlockchainImpl) GetTotalNumShards() int {
	return bc.ShardState.TotalNumShards
}

// InitializeBlockchain handles all blockchain initialization tasks
func (bc *BlockchainImpl) InitializeBlockchain() error {
	log.Printf("Starting blockchain initialization for shard %d...", bc.ShardState.ShardID)

	// Try to migrate existing balance first
	if err := bc.MigrateGenesisBalance(); err != nil {
		log.Printf("WARN: Failed to migrate genesis balance for shard %d: %v", bc.ShardState.ShardID, err)
		// Don't fail completely - continue with initialization
	}

	// Initialize with default balance if needed
	// Use the balance from stakeholders map
	bc.ShardState.Mu.Lock()
	var genesisBalance int64 = 119999999800000000 // Default fallback

	// Get genesis address
	genesisPubKey := bc.ShardState.GenesisAccount.PublicKey()
	if genesisPubKey != nil {
		genesisAddr, err := genesisPubKey.Address()
		if err == nil && genesisAddr != nil {
			genesisAddrStr := genesisAddr.String()
			if existingBalance, exists := bc.ShardState.Stakeholders[genesisAddrStr]; exists {
				genesisBalance = existingBalance
			}
		}
	}
	bc.ShardState.Mu.Unlock()

	if err := bc.InitializeGenesisBalance(genesisBalance); err != nil {
		return fmt.Errorf("failed to initialize genesis balance for shard %d: %w", bc.ShardState.ShardID, err)
	}

	// Add any other initialization tasks here for this shard

	log.Printf("Blockchain initialization completed successfully for shard %d", bc.ShardState.ShardID)
	return nil
}

// MigrateGenesisBalance migrates genesis balance from old storage to new sharded storage
func (bc *BlockchainImpl) MigrateGenesisBalance() error {
	// Get genesis address string
	genesisPubKey := bc.ShardState.GenesisAccount.PublicKey()
	if genesisPubKey == nil {
		return fmt.Errorf("genesis account public key is nil for shard %d", bc.ShardState.ShardID)
	}

	genesisAddr, err := genesisPubKey.Address()
	if err != nil {
		return fmt.Errorf("failed to get address object from genesis public key for shard %d: %v", bc.ShardState.ShardID, err)
	}
	if genesisAddr == nil {
		return fmt.Errorf("genesis public key returned nil address object for shard %d", bc.ShardState.ShardID)
	}

	genesisAddrStr := genesisAddr.String()
	totalNumShards := bc.GetTotalNumShards()

	// Check if genesis balance already exists in sharded storage
	currentBalance, err := bc.ShardState.Database.GetStakeholderBalance(genesisAddrStr, totalNumShards)
	if err != nil {
		return fmt.Errorf("failed to check existing genesis balance for shard %d: %v", bc.ShardState.ShardID, err)
	}

	// If balance already exists and is non-zero, no migration needed
	if currentBalance > 0 {
		log.Printf("DEBUG: Genesis balance already exists in sharded storage for shard %d: %d", bc.ShardState.ShardID, currentBalance)
		return nil
	}

	// Get balance from stakeholders map
	bc.ShardState.Mu.Lock()
	stakeholderBalance, exists := bc.ShardState.Stakeholders[genesisAddrStr]
	bc.ShardState.Mu.Unlock()

	if !exists || stakeholderBalance == 0 {
		log.Printf("WARN: No genesis balance found in stakeholders map for shard %d", bc.ShardState.ShardID)
		return nil
	}

	log.Printf("DEBUG: Migrating genesis balance from stakeholders map (%d) to sharded storage for shard %d", stakeholderBalance, bc.ShardState.ShardID)

	// Create transaction context
	dbTxContext, err := bc.ShardState.Database.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin transaction for genesis migration on shard %d: %v", bc.ShardState.ShardID, err)
	}

	defer func() {
		if err != nil {
			bc.ShardState.Database.RollbackTransaction(dbTxContext)
		}
	}()

	// Set the genesis balance in sharded storage
	err = bc.ShardState.Database.AddToBalance(dbTxContext, genesisAddrStr, stakeholderBalance, totalNumShards)
	if err != nil {
		return fmt.Errorf("failed to set genesis balance in sharded storage for shard %d: %v", bc.ShardState.ShardID, err)
	}

	// Commit transaction
	err = bc.ShardState.Database.CommitTransaction(dbTxContext)
	if err != nil {
		return fmt.Errorf("failed to commit genesis balance migration for shard %d: %v", bc.ShardState.ShardID, err)
	}

	log.Printf("SUCCESS: Migrated genesis balance %d to sharded storage for %s on shard %d", stakeholderBalance, genesisAddrStr, bc.ShardState.ShardID)
	return nil
}

// InitializeGenesisBalance sets up the genesis balance in sharded storage
func (bc *BlockchainImpl) InitializeGenesisBalance(initialBalance int64) error {
	// Get genesis address string
	genesisPubKey := bc.ShardState.GenesisAccount.PublicKey()
	if genesisPubKey == nil {
		return fmt.Errorf("genesis account public key is nil for shard %d", bc.ShardState.ShardID)
	}

	genesisAddr, err := genesisPubKey.Address()
	if err != nil {
		return fmt.Errorf("failed to get address object from genesis public key for shard %d: %v", bc.ShardState.ShardID, err)
	}
	if genesisAddr == nil {
		return fmt.Errorf("genesis public key returned nil address object for shard %d", bc.ShardState.ShardID)
	}

	genesisAddrStr := genesisAddr.String()
	totalNumShards := bc.GetTotalNumShards()

	// Check if already initialized
	currentBalance, err := bc.ShardState.Database.GetStakeholderBalance(genesisAddrStr, totalNumShards)
	if err != nil {
		return fmt.Errorf("failed to check existing genesis balance for shard %d: %v", bc.ShardState.ShardID, err)
	}

	if currentBalance > 0 {
		log.Printf("DEBUG: Genesis balance already initialized for shard %d: %d", bc.ShardState.ShardID, currentBalance)
		return nil
	}

	// Create transaction context
	dbTxContext, err := bc.ShardState.Database.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin transaction for genesis initialization on shard %d: %v", bc.ShardState.ShardID, err)
	}

	defer func() {
		if err != nil {
			bc.ShardState.Database.RollbackTransaction(dbTxContext)
		}
	}()

	// Set initial genesis balance
	err = bc.ShardState.Database.AddToBalance(dbTxContext, genesisAddrStr, initialBalance, totalNumShards)
	if err != nil {
		return fmt.Errorf("failed to initialize genesis balance for shard %d: %v", bc.ShardState.ShardID, err)
	}

	// Commit transaction
	err = bc.ShardState.Database.CommitTransaction(dbTxContext)
	if err != nil {
		return fmt.Errorf("failed to commit genesis balance initialization for shard %d: %v", bc.ShardState.ShardID, err)
	}

	// Update stakeholders map to match
	bc.ShardState.Mu.Lock()
	bc.ShardState.Stakeholders[genesisAddrStr] = initialBalance
	bc.ShardState.Mu.Unlock()

	log.Printf("SUCCESS: Initialized genesis balance %d for %s on shard %d", initialBalance, genesisAddrStr, bc.ShardState.ShardID)
	return nil
}
