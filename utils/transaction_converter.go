package utils

import (
	"log"

	"github.com/thrylos-labs/thrylos/crypto"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

func ConvertToSharedTransaction(tx *thrylos.Transaction) *types.Transaction {
	if tx == nil {
		log.Println("WARN: ConvertToSharedTransaction called with nil thrylos.Transaction")
		return nil
	}

	// Convert inputs
	inputs := make([]types.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		if input == nil {
			log.Printf("WARN: Skipping nil input at index %d for tx %s", i, tx.Id)
			continue
		}
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
		if output == nil {
			log.Printf("WARN: Skipping nil output at index %d for tx %s", i, tx.Id)
			continue
		}
		outputs[i] = types.UTXO{
			TransactionID: output.TransactionId,
			Index:         int(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        amount.Amount(output.Amount),
			IsSpent:       output.IsSpent,
		}
	}

	// --- *** FIX: Handle SenderAddress *** ---
	var senderAddr *address.Address // Declare variables outside the if/else
	var err error
	if tx.Sender == "" {
		// Assign zero address directly for empty sender (e.g., Genesis/Funding)
		senderAddr = &address.Address{}
		// Optional: Log info only if needed, this case is expected for genesis
		// log.Printf("DEBUG: Assigning zero sender address for tx %s with empty sender field.", tx.Id)
	} else {
		// Only parse if sender string is not empty
		senderAddr, err = address.FromString(tx.Sender)
		if err != nil {
			log.Printf("ERROR: Failed to parse non-empty sender address '%s' from proto tx %s: %v", tx.Sender, tx.Id, err)
			senderAddr = &address.Address{} // Assign zero address on parse error
		}
	}
	// --- *** END FIX *** ---

	// --- Handle SenderPublicKey --- (Keep this fix from before)
	var senderPubKey crypto.PublicKey = nil
	if len(tx.SenderPublicKey) > 0 {
		recreatedPubKey, err := crypto.NewPublicKeyFromBytes(tx.SenderPublicKey)
		if err != nil {
			log.Printf("ERROR: Failed to recreate PublicKey from proto bytes for tx %s: %v. SenderPublicKey will be nil.", tx.Id, err)
		} else {
			senderPubKey = recreatedPubKey
			log.Printf("DEBUG: Successfully recreated SenderPublicKey for tx %s", tx.Id)
		}
	} else {
		// Log warning only if not Genesis/Funding (requires IsGenesis/IsFunding logic later)
		// For now, keeping the general warning:
		log.Printf("WARN: Proto transaction %s has empty SenderPublicKey bytes.", tx.Id)
	}
	// --- END Handle SenderPublicKey ---

	// --- Handle Signature --- (Keep this fix from before)
	var signature crypto.Signature = nil
	if len(tx.Signature) > 0 {
		recreatedSig, err := crypto.NewSignatureWithError(tx.Signature)
		if err != nil {
			log.Printf("ERROR: Failed to recreate Signature from proto bytes for tx %s: %v. Signature will be nil.", tx.Id, err)
		} else {
			signature = recreatedSig
			log.Printf("DEBUG: Successfully recreated Signature for tx %s", tx.Id)
		}
	}
	// --- END Handle Signature ---

	sharedTx := &types.Transaction{
		ID:               tx.Id,
		Timestamp:        tx.Timestamp,
		Inputs:           inputs,
		Outputs:          outputs,
		EncryptedInputs:  tx.EncryptedInputs,
		EncryptedOutputs: tx.EncryptedOutputs,
		EncryptedAESKey:  tx.EncryptedAesKey, // Check proto field name consistency
		PreviousTxIds:    tx.PreviousTxIds,
		SenderAddress:    *senderAddr, // Assign dereferenced address object
		SenderPublicKey:  senderPubKey,
		Signature:        signature,
		GasFee:           int(tx.Gasfee),
		BlockHash:        string(tx.BlockHash),
		Salt:             tx.Salt,
		Status:           tx.Status,
	}

	// Final check after creating the object
	// This check still needs the IsGenesis/IsFunding methods on types.Transaction to be correct
	if sharedTx.SenderPublicKey == nil && !sharedTx.IsGenesis() && !sharedTx.IsFunding() {
		log.Printf("WARN: ConvertToSharedTransaction resulted in types.Transaction %s with nil SenderPublicKey (and not Genesis/Funding).", sharedTx.ID)
	}

	return sharedTx
}
