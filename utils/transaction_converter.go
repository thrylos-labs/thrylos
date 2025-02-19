package utils

import (
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/types"
)

// ConvertToSharedTransaction converts a thrylos.Transaction to a types.Transaction
func ConvertToSharedTransaction(tx *thrylos.Transaction) *types.Transaction {
	if tx == nil {
		return nil
	}

	// Convert inputs
	inputs := make([]types.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		inputs[i] = types.UTXO{
			TransactionID: input.TransactionId,
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        amount.Amount(input.Amount),
			IsSpent:       input.IsSpent,
		}
	}

	// Convert outputs
	outputs := make([]types.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		outputs[i] = types.UTXO{
			TransactionID: output.TransactionId,
			Index:         int(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        amount.Amount(output.Amount),
			IsSpent:       output.IsSpent,
		}
	}

	sharedTx := &types.Transaction{
		ID:               tx.Id,
		Timestamp:        tx.Timestamp,
		Inputs:           inputs,
		Outputs:          outputs,
		EncryptedInputs:  tx.EncryptedInputs,
		EncryptedOutputs: tx.EncryptedOutputs,
		EncryptedAESKey:  tx.EncryptedAesKey,
		PreviousTxIds:    tx.PreviousTxIds,
		GasFee:           int(tx.Gasfee),
		BlockHash:        string(tx.BlockHash),
		Salt:             tx.Salt,
		Status:           tx.Status,
	}

	return sharedTx
}
