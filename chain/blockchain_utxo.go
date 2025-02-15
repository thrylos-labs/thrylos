package chain

import (
	"fmt"
	"log"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/types"
)

// // // // addUTXO adds a new UTXO to the blockchain's UTXO set.
func (bc *BlockchainImpl) addUTXO(utxo types.UTXO) error {
	utxoKey := fmt.Sprintf("%s:%d", utxo.TransactionID, utxo.Index)
	log.Printf("Adding UTXO with key: %s", utxoKey)

	if _, exists := bc.Blockchain.UTXOs[utxoKey]; !exists {
		bc.Blockchain.UTXOs[utxoKey] = []*thrylos.UTXO{}
	}

	// Create a proto UTXO first
	protoUTXO := &thrylos.UTXO{
		TransactionId: utxo.TransactionID,
		Index:         int32(utxo.Index),
		OwnerAddress:  utxo.OwnerAddress,
		Amount:        int64(utxo.Amount), // You might need to convert Amount to int64
	}

	bc.Blockchain.UTXOs[utxoKey] = append(bc.Blockchain.UTXOs[utxoKey], protoUTXO)

	// Remember access blockchain struct with database in to access
	if err := bc.Blockchain.Database.AddUTXO(utxo); err != nil {
		log.Printf("Failed to add UTXO to database: %s", err)
		return err
	}

	log.Printf("UTXO successfully added: %v", utxo)
	return nil
}

// // // removeUTXO removes a UTXO from the blockchain's UTXO set based on transaction ID and index.
func (bc *BlockchainImpl) removeUTXO(transactionID string, index int32) bool {
	utxoKey := fmt.Sprintf("%s:%d", transactionID, index)
	if _, exists := bc.Blockchain.UTXOs[utxoKey]; exists {
		delete(bc.Blockchain.UTXOs, utxoKey)
		return true
	}
	return false
}

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
	balance := amount.Amount(0) // Or however Amount type is initialized
	utxos, err := bc.Blockchain.Database.GetUTXOsForAddress(address)
	if err != nil {
		return amount.Amount(0), err
	}

	for _, utxo := range utxos {
		if !utxo.IsSpent {
			balance = balance + utxo.Amount // Or use appropriate method like Add()
		}
	}
	return balance, nil
}

// // Function to convert Blockchain UTXOs to a format usable in shared validation logic
func (bc *BlockchainImpl) convertUTXOsToRequiredFormat() map[string][]types.UTXO {
	result := make(map[string][]types.UTXO)
	for key, utxos := range bc.Blockchain.UTXOs {
		sharedUtxos := make([]types.UTXO, len(utxos))
		for i, utxo := range utxos {
			sharedUtxos[i] = types.UTXO{
				TransactionID: utxo.TransactionId,
				Index:         int(utxo.Index),
				OwnerAddress:  utxo.OwnerAddress,
				Amount:        amount.Amount(int64(utxo.Amount)), // Cast int64 to amount.Amount
			}
		}
		result[key] = sharedUtxos
	}
	return result
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
