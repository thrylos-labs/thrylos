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

	return bc.Blockchain.Database.AddUTXO(utxo)
}

func (bc *BlockchainImpl) GetUTXOsForAddress(address string) ([]types.UTXO, error) {
	log.Printf("Fetching UTXOs for address: %s", address)
	utxos, err := bc.Blockchain.Database.GetUTXOsForAddress(address)
	if err != nil {
		log.Printf("Failed to fetch UTXOs from database: %s", err)
		return nil, err
	}
	log.Printf("Retrieved %d UTXOs for address %s", len(utxos), address)
	return utxos, nil
}

func (bc *BlockchainImpl) GetAllUTXOs() (map[string][]types.UTXO, error) {
	return bc.Blockchain.Database.GetAllUTXOs()
}

func (bc *BlockchainImpl) GetUTXOsForUser(address string) ([]types.UTXO, error) {
	return bc.Blockchain.Database.GetUTXOsForUser(address)
}

// // Always deals with nanoTHRYLOS as int64
func (bc *BlockchainImpl) GetBalance(address string) (amount.Amount, error) {
	bc.Blockchain.Mu.RLock() // Lock for reading the UTXOs map
	defer bc.Blockchain.Mu.RUnlock()

	log.Printf("DEBUG: [GetBalance] Calculating balance for %s from in-memory UTXO map (%d entries)", address, len(bc.Blockchain.UTXOs))
	balance := amount.Amount(0)

	// Iterate through the in-memory UTXO map (map[string][]*thrylos.UTXO)
	// This requires checking the OwnerAddress field of the stored *thrylos.UTXO objects
	for key, utxoSlice := range bc.Blockchain.UTXOs {
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
