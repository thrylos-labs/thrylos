package chain

import (
	"fmt"
	"log"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/types"
)

func (bc *BlockchainImpl) CreateInitialWalletUTXO(address string, initialBalance int64) error {
	utxo := types.UTXO{
		OwnerAddress:  address,
		Amount:        amount.Amount(int64(initialBalance)),
		TransactionID: fmt.Sprintf("genesis-%s", address),
		IsSpent:       false,
		Index:         0, // Use 0 for initial UTXO
	}

	return bc.ShardState.Database.AddUTXO(utxo)
}

func (bc *BlockchainImpl) GetUTXOsForAddress(address string) ([]types.UTXO, error) {
	log.Printf("Fetching UTXOs for address: %s (Shard: %d)", address, bc.ShardState.ShardID)

	// Get the total number of shards from the AppConfig or ChainState
	totalNumShards := bc.AppConfig.NumShards // Or bc.ShardState.TotalNumShards

	// Pass the totalNumShards as the second argument to the database call
	utxos, err := bc.ShardState.Database.GetUTXOsForAddress(address, totalNumShards) // FIXED: Added totalNumShards
	if err != nil {
		log.Printf("Failed to fetch UTXOs from database for address %s (Shard: %d): %s", address, bc.ShardState.ShardID, err)
		return nil, err
	}
	log.Printf("Retrieved %d UTXOs for address %s (Shard: %d)", len(utxos), address, bc.ShardState.ShardID)
	return utxos, nil
}

func (bc *BlockchainImpl) GetAllUTXOs() (map[string][]types.UTXO, error) {
	return bc.ShardState.Database.GetAllUTXOs()
}

func (bc *BlockchainImpl) GetUTXOsForUser(address string) ([]types.UTXO, error) {
	return bc.ShardState.Database.GetUTXOsForUser(address)
}

// // Always deals with nanoTHRYLOS as int64
func (bc *BlockchainImpl) GetBalance(address string) (amount.Amount, error) {
	bc.ShardState.Mu.RLock() // Lock for reading the UTXOs map
	defer bc.ShardState.Mu.RUnlock()

	log.Printf("DEBUG: [GetBalance] Calculating balance for %s from in-memory UTXO map (%d entries)", address, len(bc.ShardState.UTXOs))
	balance := amount.Amount(0)

	// Iterate through the in-memory UTXO map (map[string][]*thrylos.UTXO)
	// This requires checking the OwnerAddress field of the stored *thrylos.UTXO objects
	for key, utxoSlice := range bc.ShardState.UTXOs {
		// The key itself might not contain the address if using "txid-index" format.
		// We need to check the UTXOs within the slice.
		for _, protoUtxo := range utxoSlice {
			if protoUtxo != nil && protoUtxo.OwnerAddress == address {
				// Found an unspent UTXO belonging to the address
				// Note: We assume UTXOs in this map are unspent. `updateStateForBlock` removes spent ones.
				balance += amount.Amount(protoUtxo.Amount) // Add amount
				log.Printf("DEBUG: [GetBalance] Added UTXO %s (Amount: %d)", key, protoUtxo.Amount)
			}
		}
	}

	log.Printf("DEBUG: [GetBalance] Calculated balance for %s: %d", address, balance)
	return balance, nil
}

// // // ConvertProtoUTXOToShared converts a Protobuf-generated UTXO to your shared UTXO type.
func ConvertProtoUTXOToShared(protoUTXO *thrylos.UTXO) types.UTXO {
	return types.UTXO{
		ID:            protoUTXO.GetTransactionId(), // Assuming you have corresponding fields
		TransactionID: protoUTXO.GetTransactionId(),
		Index:         int(protoUTXO.GetIndex()), // Convert from int32 to int if necessary
		OwnerAddress:  protoUTXO.GetOwnerAddress(),
		Amount:        amount.Amount(int64(protoUTXO.GetAmount())), // Convert from int64 to int if necessary
	}
}
