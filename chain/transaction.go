package chain

import (
	"bytes"
	"fmt"
	"log"
	"strconv"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

func ConvertToThrylosTransaction(tx *types.Transaction) (*thrylos.Transaction, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil transaction")
	}

	// Convert inputs and outputs
	thrylosInputs := make([]*thrylos.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		thrylosInputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        input.Amount.ToNanoTHR(),
		}
	}

	thrylosOutputs := make([]*thrylos.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		thrylosOutputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        output.Amount.ToNanoTHR(),
		}
	}

	return &thrylos.Transaction{
		Id:            tx.ID,
		Inputs:        thrylosInputs,
		Outputs:       thrylosOutputs,
		Timestamp:     tx.Timestamp,
		PreviousTxIds: tx.PreviousTxIds,
		Gasfee:        int32(tx.GasFee),
	}, nil
}

func SharedToThrylosInputs(inputs []types.UTXO, txSender string) []*thrylos.UTXO {
	if len(inputs) == 0 {
		log.Printf("WARNING: No inputs provided to SharedToThrylosInputs")
		return nil
	}

	log.Printf("Converting %d inputs to Thrylos format", len(inputs))
	thrylosInputs := make([]*thrylos.UTXO, len(inputs))

	for i, input := range inputs {
		log.Printf("DEBUG: Raw input UTXO before conversion: %+v", input)

		// Check for missing transaction ID
		if input.TransactionID == "" {
			log.Printf("ERROR: Input UTXO missing transaction ID: %+v", input)
			continue // or handle this error appropriately
		}

		ownerAddress := input.OwnerAddress
		if ownerAddress == "" {
			log.Printf("DEBUG: Input owner address is empty, using sender: %s", txSender)
			ownerAddress = txSender
		}

		// Convert amount.Amount to int64
		amountInt64 := input.Amount.ToNanoTHR() // or input.Amount.Int64() depending on your amount package

		thrylosInputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         int32(input.Index),
			OwnerAddress:  ownerAddress,
			Amount:        amountInt64, // Using the converted amount
			IsSpent:       input.IsSpent,
		}

		// Verify the conversion
		log.Printf("DEBUG: Converted Thrylos UTXO ID: %s", thrylosInputs[i].TransactionId)
		log.Printf("DEBUG: Converted Thrylos UTXO: %+v", thrylosInputs[i])
	}

	return thrylosInputs
}

func SharedToThrylosOutputs(outputs []types.UTXO) []*thrylos.UTXO {
	if len(outputs) == 0 {
		log.Printf("WARNING: No outputs provided to SharedToThrylosOutputs")
		return nil
	}

	thrylosOutputs := make([]*thrylos.UTXO, len(outputs))
	for i, output := range outputs {
		// Add validation logging
		log.Printf("Output %d details:", i)
		log.Printf("- OwnerAddress: %s", output.OwnerAddress)
		log.Printf("- Amount: %d", output.Amount)

		if output.OwnerAddress == "" {
			log.Printf("WARNING: Empty owner address for output %d", i)
		}

		thrylosOutputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
		}

		// Verify conversion
		log.Printf("Converted Output %d details:", i)
		log.Printf("- OwnerAddress: %s", thrylosOutputs[i].OwnerAddress)
		log.Printf("- Amount: %d", thrylosOutputs[i].Amount)
	}

	return thrylosOutputs
}

// First, add this helper function (either in your package or the address package):
func AddressFromString(addrStr string) (*address.Address, error) {
	if !address.Validate(addrStr) {
		return nil, fmt.Errorf("invalid address format: %s", addrStr)
	}

	_, decoded, err := bech32.Decode(addrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %v", err)
	}

	var addr address.Address
	copy(addr[:], decoded)
	return &addr, nil
}

// Then modify the conversion function:
func ConvertThrylosTransactionToLocal(tx *thrylos.Transaction) (types.Transaction, error) {
	if tx.Sender == "" {
		return types.Transaction{}, fmt.Errorf("transaction sender is empty")
	}

	// Convert inputs
	localInputs := make([]types.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		amt, err := amount.NewAmount(float64(input.Amount))
		if err != nil {
			return types.Transaction{}, fmt.Errorf("failed to convert input amount: %v", err)
		}
		localInputs[i] = types.UTXO{
			TransactionID: input.TransactionId,
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        amt,
		}
	}

	// Convert outputs
	localOutputs := make([]types.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		amt, err := amount.NewAmount(float64(output.Amount))
		if err != nil {
			return types.Transaction{}, fmt.Errorf("failed to convert output amount: %v", err)
		}
		localOutputs[i] = types.UTXO{
			TransactionID: output.TransactionId,
			Index:         int(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        amt,
		}
	}

	// Convert signature
	signature := crypto.NewSignature(tx.Signature)

	// Convert address
	addr, err := AddressFromString(tx.Sender)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("failed to convert sender address: %v", err)
	}

	return types.Transaction{
		ID:            tx.Id,
		SenderAddress: *addr, // Note: dereferencing the pointer
		Inputs:        localInputs,
		Outputs:       localOutputs,
		Timestamp:     tx.Timestamp,
		Signature:     signature,
		PreviousTxIds: tx.PreviousTxIds,
		GasFee:        int(tx.Gasfee),
	}, nil
}

// First, define a type for the public key lookup function
type PublicKeyFetcher func(string) (crypto.PublicKey, error)

// Then update the verification function
func VerifyTransactionData(tx *thrylos.Transaction, utxos map[string][]*thrylos.UTXO, getPublicKey PublicKeyFetcher) (bool, error) {
	// Validate salt exists and has proper length
	if len(tx.Salt) == 0 {
		return false, fmt.Errorf("transaction must have a salt value")
	}
	if len(tx.Salt) != 32 {
		return false, fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// Validate inputs and outputs exist
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return false, fmt.Errorf("transaction must have inputs and outputs")
	}

	// Get the public key using the fetcher
	pubKey, err := getPublicKey(tx.Sender)
	if err != nil {
		return false, fmt.Errorf("invalid sender address: %v", err)
	}

	// Create transaction data bundle including salt for signature verification
	txDataBundle := createTransactionDataBundle(tx)

	// Create signature from transaction signature bytes
	sig := crypto.NewSignature(tx.Signature)

	// Verify signature using our crypto package
	if err := pubKey.Verify(txDataBundle, &sig); err != nil {
		return false, fmt.Errorf("invalid transaction signature: %v", err)
	}

	// Rest of your verification logic remains the same
	for _, input := range tx.Inputs {
		if input.OwnerAddress != tx.Sender {
			return false, fmt.Errorf("input owner address does not match sender")
		}

		utxoKey := fmt.Sprintf("%s:%d", input.TransactionId, input.Index)
		utxoList, exists := utxos[utxoKey]
		if !exists || len(utxoList) == 0 {
			return false, fmt.Errorf("input UTXO not found: %s", utxoKey)
		}

		if utxoList[0].Amount != input.Amount {
			return false, fmt.Errorf("input amount mismatch for UTXO: %s", utxoKey)
		}
	}

	// Balance verification
	inputSum := int64(0)
	for _, input := range tx.Inputs {
		inputSum += input.Amount
	}

	outputSum := int64(0)
	for _, output := range tx.Outputs {
		outputSum += output.Amount
	}

	if inputSum != outputSum+int64(tx.Gasfee) {
		return false, fmt.Errorf("input amount (%d) does not match output amount (%d) plus gas fee (%d)",
			inputSum, outputSum, tx.Gasfee)
	}

	return true, nil
}

// Helper function to create a transaction data bundle for verification
func createTransactionDataBundle(tx *thrylos.Transaction) []byte {
	// Create a deterministic bundle of transaction data including the salt
	var bundle [][]byte

	// Add transaction components in a fixed order
	bundle = append(bundle, []byte(tx.Id))
	bundle = append(bundle, tx.Salt)
	bundle = append(bundle, []byte(strconv.FormatInt(tx.Timestamp, 10)))

	// Add input data
	for _, input := range tx.Inputs {
		inputData := []byte(fmt.Sprintf("%s:%d:%d",
			input.TransactionId,
			input.Index,
			input.Amount))
		bundle = append(bundle, inputData)
	}

	// Add output data
	for _, output := range tx.Outputs {
		outputData := []byte(fmt.Sprintf("%s:%d",
			output.OwnerAddress,
			output.Amount))
		bundle = append(bundle, outputData)
	}

	// Add gas fee
	bundle = append(bundle, []byte(strconv.FormatInt(int64(tx.Gasfee), 10)))

	// Join all components with a separator
	return bytes.Join(bundle, []byte("|"))
}

func convertInputsToJSON(inputs []*thrylos.UTXO) []map[string]interface{} {
	result := make([]map[string]interface{}, len(inputs))
	for i, input := range inputs {
		result[i] = map[string]interface{}{
			"amount":        input.Amount,
			"index":         int(input.Index),
			"owner_address": input.OwnerAddress,
		}
	}
	return result
}

func convertOutputsToJSON(outputs []*thrylos.UTXO) []map[string]interface{} {
	result := make([]map[string]interface{}, len(outputs))
	for i, output := range outputs {
		result[i] = map[string]interface{}{
			"amount":        output.Amount,
			"index":         int(output.Index),
			"owner_address": output.OwnerAddress,
		}
	}
	return result
}

// ConvertSharedToThrylos converts a shared.Transaction to a thrylos.Transaction.
// func ValidateAndConvertTransaction(
// 	tx *thrylos.Transaction,
// 	db types.Store, // Changed from BlockchainDBInterface to types.Store
// 	publicKey *mldsa44.PublicKey,
// 	estimator utils.GasEstimator,
// 	balance int64,
// ) error {
// 	if tx == nil {
// 		return fmt.Errorf("transaction is nil")
// 	}
// 	if db == nil {
// 		return fmt.Errorf("database interface is nil")
// 	}
// 	if estimator == nil {
// 		return fmt.Errorf("gas estimator is nil")
// 	}
// 	if publicKey == nil {
// 		return fmt.Errorf("public key is nil")
// 	}

// 	// Validate sender exists in system
// 	if tx.Sender == "" {
// 		return fmt.Errorf("transaction sender is empty")
// 	}

// 	// Verify the public key matches the sender's address
// 	derivedAddress, err := deriveAddressFromPublicKey(publicKey)
// 	if err != nil {
// 		return fmt.Errorf("failed to derive address from public key: %v", err)
// 	}
// 	if derivedAddress != tx.Sender {
// 		return fmt.Errorf("public key does not match sender address")
// 	}

// 	// Convert and validate the rest of the transaction
// 	localTx, err := ConvertThrylosTransactionToLocal(tx)
// 	if err != nil {
// 		return fmt.Errorf("failed to convert transaction to shared type: %v", err)
// 	}

// 	if err := shared.ValidateTransactionBalance(&localTx); err != nil {
// 		return fmt.Errorf("invalid transaction: %v", err)
// 	}

// 	return nil
// }

func deriveAddressFromPublicKey(publicKey *mldsa44.PublicKey) (string, error) {
	// Get the public key bytes
	publicKeyBytes := publicKey.Bytes()

	// Convert public key bytes to 5-bit words for bech32 encoding
	words, err := bech32.ConvertBits(publicKeyBytes, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key to 5-bit words: %v", err)
	}

	// Encode with your tl1 prefix (matching your frontend)
	address, err := bech32.Encode("tl1", words)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32 address: %v", err)
	}

	return address, nil
}

func createExactCanonicalForm(tx *thrylos.Transaction) map[string]interface{} {
	inputs := make([]map[string]interface{}, len(tx.Inputs))
	for i, input := range tx.Inputs {
		inputs[i] = map[string]interface{}{
			"amount": input.Amount,
			"index":  input.Index,
		}
	}

	outputs := make([]map[string]interface{}, len(tx.Outputs))
	for i, output := range tx.Outputs {
		outputs[i] = map[string]interface{}{
			"amount": output.Amount,
			"index":  output.Index,
		}
	}

	return map[string]interface{}{
		"gasfee":          tx.Gasfee,
		"id":              tx.Id,
		"inputs":          inputs,
		"outputs":         outputs,
		"previous_tx_ids": tx.PreviousTxIds,
		"sender":          tx.Sender,
		"status":          "pending",
		"timestamp":       tx.Timestamp,
	}
}
