// types/utxo_utils.go
package types

import "github.com/thrylos-labs/thrylos/amount"

// CreateUTXO creates a new UTXO instance
func CreateUTXO(id string, index int, txID string, owner string, coinAmount float64, isSpent bool) *UTXO {
	formatedAmount, err := amount.NewAmount(coinAmount)
	if err != nil {
		return nil
	}
	return &UTXO{
		ID:            id,
		Index:         index,
		TransactionID: txID,
		OwnerAddress:  owner,
		Amount:        formatedAmount,
		IsSpent:       isSpent,
	}
}

// MarkUTXOAsSpent removes a UTXO from the set of available UTXOs
func MarkUTXOAsSpent(utxoID string, allUTXOs map[string]UTXO) {
	delete(allUTXOs, utxoID)
}
