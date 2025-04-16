package utils

import (
	"fmt"
	"log"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/types"
)

func ThrylosToNano(thrylos ...float64) int64 {
	var amount float64
	if len(thrylos) > 0 {
		amount = thrylos[0]
	} else {
		amount = config.InitialTotalSupply
	}
	return int64(amount * config.NanoPerThrylos)
}

func NanoToThrylos(nano int64) float64 {
	return float64(nano) / config.NanoPerThrylos
}

// ConvertMultipleToProto converts a slice of shared Transactions to protobuf Transactions
func ConvertMultipleToProto(sharedTxs []*types.Transaction) ([]*thrylos.Transaction, error) {
	protoTxs := make([]*thrylos.Transaction, 0, len(sharedTxs))
	for i, sharedTx := range sharedTxs {
		if sharedTx == nil {
			log.Printf("Warning: Skipping nil shared transaction at index %d during multi-conversion", i)
			continue
		}
		protoTx := ConvertToProtoTransaction(sharedTx) // Use the single conversion helper
		if protoTx == nil {
			// Decide how to handle nil conversion - skip or return error?
			// Returning error for now is safer.
			return nil, fmt.Errorf("failed to convert shared transaction %s to proto at index %d", sharedTx.ID, i)
		}
		protoTxs = append(protoTxs, protoTx)
	}
	return protoTxs, nil
}

// ConvertToProtoTransaction converts a single shared Transaction (*types.Transaction)
// to a protobuf Transaction (*thrylos.Transaction).
// (This is based on your previous convertToThrylosTransaction function)
func ConvertToProtoTransaction(tx *types.Transaction) *thrylos.Transaction {
	if tx == nil {
		return nil
	}

	// Convert Inputs (types.UTXO to *thrylos.UTXO)
	inputs := make([]*thrylos.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs { // input is types.UTXO
		inputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index),
			OwnerAddress:  input.OwnerAddress,  // types.UTXO uses string address
			Amount:        int64(input.Amount), // Convert amount.Amount to int64
			IsSpent:       input.IsSpent,
		}
	}

	// Convert Outputs (types.UTXO to *thrylos.UTXO)
	outputs := make([]*thrylos.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs { // output is types.UTXO
		outputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,  // types.UTXO uses string address
			Amount:        int64(output.Amount), // Convert amount.Amount to int64
			IsSpent:       output.IsSpent,
		}
	}

	// Convert Signature (crypto.Signature to []byte)
	var sigBytes []byte
	if tx.Signature != nil {
		sigBytes = tx.Signature.Bytes() // Assuming Bytes() method exists
	}

	// Convert PublicKey (crypto.PublicKey to []byte)
	var pkBytes []byte
	if tx.SenderPublicKey != nil {
		var err error
		pkBytes, err = tx.SenderPublicKey.Marshal() // Assuming MarshalBinary exists
		if err != nil {
			log.Printf("ERROR converting PublicKey to bytes for Tx %s: %v", tx.ID, err)
			// Handle error? Return nil? Continue with nil pkBytes?
			pkBytes = nil // Set to nil on error for now
		}
	}

	// Convert Address (address.Address to string)
	senderAddrStr := ""
	// Check if SenderAddress itself is nil pointer before calling String() if it's a pointer type
	// Assuming SenderAddress is address.Address value type based on types.Transaction struct
	senderAddrStr = tx.SenderAddress.String()

	thrylosTx := &thrylos.Transaction{
		Id:               tx.ID,
		Timestamp:        tx.Timestamp,
		Inputs:           inputs,
		Outputs:          outputs,
		EncryptedInputs:  tx.EncryptedInputs,
		EncryptedOutputs: tx.EncryptedOutputs,
		EncryptedAesKey:  tx.EncryptedAESKey,
		PreviousTxIds:    tx.PreviousTxIds,
		Gasfee:           int32(tx.GasFee),     // Convert int to int32
		BlockHash:        []byte(tx.BlockHash), // Convert string to []byte
		Salt:             tx.Salt,
		Status:           tx.Status,
		Signature:        sigBytes,
		SenderPublicKey:  pkBytes,
		Sender:           senderAddrStr, // Use converted string
	}

	return thrylosTx
}
