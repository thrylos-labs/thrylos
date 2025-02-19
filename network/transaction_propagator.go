package network

import (
	"fmt"
	"log"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/types"
)

// The TransactionPropagator ensures that when a new transaction is added to the blockchain,
// all validators (network participants who verify transactions) receive a copy of it.
// This keeps the network in sync by making sure everyone is working with the same transactions.

type TransactionPropagatorWrapper struct {
	*types.TransactionPropagator
	TxPool types.TxPool
}

func NewTransactionPropagator(bc types.BlockchainInterface) *types.TransactionPropagator {
	return &types.TransactionPropagator{
		Blockchain: bc,
	}
}

func (tpw *TransactionPropagatorWrapper) PropagateTransaction(tx *thrylos.Transaction) error {
	tpw.TransactionPropagator.Mu.Lock()
	defer tpw.TransactionPropagator.Mu.Unlock()

	// Get active validators using the interface method
	validators := tpw.TransactionPropagator.Blockchain.GetActiveValidators()
	if len(validators) == 0 {
		return fmt.Errorf("no active validators")
	}

	// Simple propagation to each validator
	for _, validatorAddr := range validators {
		if err := tpw.sendToValidator(tx, validatorAddr); err != nil {
			log.Printf("Failed to propagate to validator %s: %v", validatorAddr, err)
			continue
		}
		log.Printf("Transaction %s propagated to validator %s", tx.Id, validatorAddr)
	}

	return nil
}

func (tpw *TransactionPropagatorWrapper) sendToValidator(tx *thrylos.Transaction, validatorAddr string) error {
	// Convert thrylos.Transaction to types.Transaction directly in this package
	typeTx := convertToSharedTransaction(tx)

	// Add transaction directly to the transaction pool
	if err := tpw.TxPool.AddTransaction(typeTx); err != nil {
		return fmt.Errorf("failed to add to transaction pool: %v", err)
	}

	log.Printf("Transaction %s added to validator %s's pool", tx.Id, validatorAddr)
	return nil
}

// Local implementation of the conversion function
func convertToSharedTransaction(tx *thrylos.Transaction) *types.Transaction {
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
		Signature:        nil,
	}

	return sharedTx
}
