package chain

import (
	"fmt"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/shared"
)

// lockchain-specific operations and processing

// TransactionContext manages blockchain-specific transaction operations

func ValidateTransaction(tx *shared.Transaction, availableUTXOs map[string][]shared.UTXO) error {
	// First perform basic structure validation
	if err := tx.ValidateStructure(); err != nil {
		return fmt.Errorf("structure validation failed: %w", err)
	}

	// Blockchain-specific validation
	inputSum := amount.Amount(0)
	for _, input := range tx.Inputs {
		// Construct the key used to find the UTXOs for this input
		utxoKey := input.Key() // Use the standardized Key() method from shared.UTXO
		utxos, exists := availableUTXOs[utxoKey]

		if !exists || len(utxos) == 0 {
			return fmt.Errorf("input UTXO not found or empty slice: %s", utxoKey)
		}

		// Verify UTXO ownership and amount
		if utxos[0].OwnerAddress != tx.SenderAddress.String() {
			return fmt.Errorf("UTXO owner mismatch for: %s", utxoKey)
		}

		inputSum += utxos[0].Amount
	}

	// Calculate output sum
	outputSum := amount.Amount(0)
	for _, output := range tx.Outputs {
		outputSum += output.Amount
	}

	// Validate balance including gas fee
	if inputSum != outputSum+amount.Amount(tx.GasFee) {
		return fmt.Errorf("input sum (%d) does not match output sum (%d) plus gas fee (%d)",
			inputSum, outputSum, tx.GasFee)
	}
	return nil
}

// Blockchain-specific conversion functions
func ConvertToThrylosTransaction(tx *shared.Transaction) (*thrylos.Transaction, error) {
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

// GetUTXOs retrieves UTXOs for a specific address from the transaction context
// func (tc *TransactionContext) GetUTXOs(address string) []shared.UTXO {
// 	tc.mu.RLock()
// 	defer tc.mu.RUnlock()
// 	return tc.UTXOs[address]
// }

// MarkModified marks an address as having modified UTXOs
// func (tc *TransactionContext) MarkModified(address string) {
// 	tc.mu.Lock()
// 	defer tc.mu.Unlock()
// 	tc.Modified[address] = true
// }

func CreateThrylosTransaction(id int) *thrylos.Transaction {
	return &thrylos.Transaction{
		Id:        fmt.Sprintf("tx%d", id),
		Inputs:    []*thrylos.UTXO{{TransactionId: "prev-tx-id", Index: 0, OwnerAddress: "Alice", Amount: 100}},
		Outputs:   []*thrylos.UTXO{{TransactionId: fmt.Sprintf("tx%d", id), Index: 0, OwnerAddress: "Bob", Amount: 100}},
		Timestamp: time.Now().Unix(),
		Signature: []byte("signature"), // This should be properly generated or mocked
		Sender:    "Alice",
	}
}

// func SharedToThrylos(tx *Transaction) *thrylos.Transaction {
// 	if tx == nil {
// 		log.Printf("SharedToThrylos received nil transaction")
// 		return nil
// 	}

// 	log.Printf("Converting transaction - Sender before: %s", tx.Sender)

// 	signatureBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
// 	if err != nil {
// 		log.Printf("Failed to decode signature: %v", err)
// 		return nil
// 	}

// 	thrylosTx := &thrylos.Transaction{
// 		Id:            tx.ID,
// 		Sender:        tx.Sender,
// 		Timestamp:     tx.Timestamp,
// 		Inputs:        SharedToThrylosInputs(tx.Inputs, tx.Sender), // Pass the sender
// 		Outputs:       SharedToThrylosOutputs(tx.Outputs),
// 		Signature:     signatureBytes,
// 		PreviousTxIds: tx.PreviousTxIds,
// 		Gasfee:        int32(tx.GasFee),
// 	}

// 	log.Printf("Converting transaction - Sender after: %s", thrylosTx.Sender)

// 	return thrylosTx
// }

// func SharedToThrylosInputs(inputs []UTXO, txSender string) []*thrylos.UTXO {
// 	if len(inputs) == 0 {
// 		log.Printf("WARNING: No inputs provided to SharedToThrylosInputs")
// 		return nil
// 	}

// 	log.Printf("Converting %d inputs to Thrylos format", len(inputs))
// 	thrylosInputs := make([]*thrylos.UTXO, len(inputs))

// 	for i, input := range inputs {
// 		log.Printf("DEBUG: Raw input UTXO before conversion: %+v", input)

// 		// Check for missing transaction ID
// 		if input.TransactionID == "" {
// 			log.Printf("ERROR: Input UTXO missing transaction ID: %+v", input)
// 			continue // or handle this error appropriately
// 		}

// 		ownerAddress := input.OwnerAddress
// 		if ownerAddress == "" {
// 			log.Printf("DEBUG: Input owner address is empty, using sender: %s", txSender)
// 			ownerAddress = txSender
// 		}

// 		thrylosInputs[i] = &thrylos.UTXO{
// 			TransactionId: input.TransactionID, // Make sure this field matches your protobuf definition
// 			Index:         int32(input.Index),
// 			OwnerAddress:  ownerAddress,
// 			Amount:        input.Amount,
// 			IsSpent:       input.IsSpent,
// 		}

// 		// Verify the conversion
// 		log.Printf("DEBUG: Converted Thrylos UTXO ID: %s", thrylosInputs[i].TransactionId)
// 		log.Printf("DEBUG: Converted Thrylos UTXO: %+v", thrylosInputs[i])
// 	}

// 	return thrylosInputs
// }

// func SharedToThrylosOutputs(outputs []UTXO) []*thrylos.UTXO {
// 	if len(outputs) == 0 {
// 		log.Printf("WARNING: No outputs provided to SharedToThrylosOutputs")
// 		return nil
// 	}

// 	thrylosOutputs := make([]*thrylos.UTXO, len(outputs))
// 	for i, output := range outputs {
// 		// Add validation logging
// 		log.Printf("Output %d details:", i)
// 		log.Printf("- OwnerAddress: %s", output.OwnerAddress)
// 		log.Printf("- Amount: %d", output.Amount)

// 		if output.OwnerAddress == "" {
// 			log.Printf("WARNING: Empty owner address for output %d", i)
// 		}

// 		thrylosOutputs[i] = &thrylos.UTXO{
// 			TransactionId: output.TransactionID,
// 			Index:         int32(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount),
// 		}

// 		// Verify conversion
// 		log.Printf("Converted Output %d details:", i)
// 		log.Printf("- OwnerAddress: %s", thrylosOutputs[i].OwnerAddress)
// 		log.Printf("- Amount: %d", thrylosOutputs[i].Amount)
// 	}

// 	return thrylosOutputs
// }

// // Hypothetical conversion function from your local Transaction type to *thrylos.Transaction
// // ConvertLocalTransactionToThrylosTransaction converts your local Transaction type to *thrylos.Transaction
// func ConvertLocalTransactionToThrylosTransaction(tx Transaction) (*thrylos.Transaction, error) {
// 	thrylosInputs := make([]*thrylos.UTXO, len(tx.Inputs))
// 	for i, input := range tx.Inputs {
// 		thrylosInputs[i] = &thrylos.UTXO{
// 			TransactionId: input.TransactionID,
// 			Index:         int32(input.Index),
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        int64(input.Amount),
// 		}
// 	}

// 	thrylosOutputs := make([]*thrylos.UTXO, len(tx.Outputs))
// 	for i, output := range tx.Outputs {
// 		thrylosOutputs[i] = &thrylos.UTXO{
// 			TransactionId: output.TransactionID,
// 			Index:         int32(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount),
// 		}
// 	}

// 	return &thrylos.Transaction{
// 		Id:            tx.ID,
// 		Inputs:        thrylosInputs,
// 		Outputs:       thrylosOutputs,
// 		Timestamp:     tx.Timestamp,
// 		PreviousTxIds: tx.PreviousTxIds, // Ensure this matches your local struct field
// 		Gasfee:        int32(tx.GasFee), // Convert the gas fee
// 		// Signature is left out to be filled during signing
// 	}, nil
// }

// // ConvertThrylosTransactionToLocal converts a thrylos.Transaction back to your local Transaction type
// // Updated
// func ConvertThrylosTransactionToLocal(tx *thrylos.Transaction) (Transaction, error) {
// 	if tx.Sender == "" {
// 		return Transaction{}, fmt.Errorf("transaction sender is empty")
// 	}

// 	localInputs := make([]UTXO, len(tx.Inputs))
// 	for i, input := range tx.Inputs {
// 		localInputs[i] = UTXO{
// 			TransactionID: input.TransactionId,
// 			Index:         int(input.Index),
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        int64(input.Amount),
// 		}
// 	}

// 	localOutputs := make([]UTXO, len(tx.Outputs))
// 	for i, output := range tx.Outputs {
// 		localOutputs[i] = UTXO{
// 			TransactionID: output.TransactionId,
// 			Index:         int(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount),
// 		}
// 	}

// 	signatureEncoded := base64.StdEncoding.EncodeToString(tx.Signature)

// 	return Transaction{
// 		ID:            tx.Id,
// 		Sender:        tx.Sender,
// 		Inputs:        localInputs,
// 		Outputs:       localOutputs,
// 		Timestamp:     tx.Timestamp,
// 		Signature:     signatureEncoded,
// 		PreviousTxIds: tx.PreviousTxIds,
// 		GasFee:        int(tx.Gasfee),
// 	}, nil
// }

// func VerifyTransactionData(tx *thrylos.Transaction, utxos map[string][]*thrylos.UTXO, getPublicKeyFunc GetPublicKeyFunc) (bool, error) {
// 	// Validate salt exists and has proper length
// 	if len(tx.Salt) == 0 {
// 		return false, fmt.Errorf("transaction must have a salt value")
// 	}
// 	if len(tx.Salt) != 32 { // Ensuring proper salt length
// 		return false, fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
// 	}

// 	// Validate inputs and outputs exist
// 	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
// 		return false, fmt.Errorf("transaction must have inputs and outputs")
// 	}

// 	// Validate sender exists in system
// 	pubKeyBytes, err := getPublicKeyFunc(tx.Sender)
// 	if err != nil {
// 		return false, fmt.Errorf("invalid sender address: %v", err)
// 	}

// 	// Convert bytes to MLDSA public key
// 	pubKey := new(mldsa44.PublicKey)
// 	if err := pubKey.UnmarshalBinary(pubKeyBytes); err != nil {
// 		return false, fmt.Errorf("failed to parse public key: %v", err)
// 	}

// 	// Create transaction data bundle including salt for signature verification
// 	txDataBundle := createTransactionDataBundle(tx)

// 	// Verify signature using ML-DSA44 with the salt-included data bundle
// 	if !mldsa44.Verify(pubKey, txDataBundle, nil, tx.Signature) {
// 		return false, fmt.Errorf("invalid transaction signature")
// 	}

// 	// Verify inputs
// 	for _, input := range tx.Inputs {
// 		if input.OwnerAddress != tx.Sender {
// 			return false, fmt.Errorf("input owner address does not match sender")
// 		}

// 		// Verify UTXO exists and is unspent
// 		utxoKey := fmt.Sprintf("%s:%d", input.TransactionId, input.Index)
// 		utxoList, exists := utxos[utxoKey]
// 		if !exists || len(utxoList) == 0 {
// 			return false, fmt.Errorf("input UTXO not found: %s", utxoKey)
// 		}

// 		// Verify UTXO amount matches
// 		if utxoList[0].Amount != input.Amount {
// 			return false, fmt.Errorf("input amount mismatch for UTXO: %s", utxoKey)
// 		}
// 	}

// 	// Verify amounts balance
// 	inputSum := int64(0)
// 	for _, input := range tx.Inputs {
// 		inputSum += input.Amount
// 	}

// 	outputSum := int64(0)
// 	for _, output := range tx.Outputs {
// 		outputSum += output.Amount
// 	}

// 	// Account for gas fee
// 	if inputSum != outputSum+int64(tx.Gasfee) {
// 		return false, fmt.Errorf("input amount (%d) does not match output amount (%d) plus gas fee (%d)",
// 			inputSum, outputSum, tx.Gasfee)
// 	}

// 	return true, nil
// }

// // Helper function to create a transaction data bundle for verification
// func createTransactionDataBundle(tx *thrylos.Transaction) []byte {
// 	// Create a deterministic bundle of transaction data including the salt
// 	var bundle [][]byte

// 	// Add transaction components in a fixed order
// 	bundle = append(bundle, []byte(tx.Id))
// 	bundle = append(bundle, tx.Salt)
// 	bundle = append(bundle, []byte(strconv.FormatInt(tx.Timestamp, 10)))

// 	// Add input data
// 	for _, input := range tx.Inputs {
// 		inputData := []byte(fmt.Sprintf("%s:%d:%d",
// 			input.TransactionId,
// 			input.Index,
// 			input.Amount))
// 		bundle = append(bundle, inputData)
// 	}

// 	// Add output data
// 	for _, output := range tx.Outputs {
// 		outputData := []byte(fmt.Sprintf("%s:%d",
// 			output.OwnerAddress,
// 			output.Amount))
// 		bundle = append(bundle, outputData)
// 	}

// 	// Add gas fee
// 	bundle = append(bundle, []byte(strconv.FormatInt(int64(tx.Gasfee), 10)))

// 	// Join all components with a separator
// 	return bytes.Join(bundle, []byte("|"))
// }

// func convertInputsToJSON(inputs []*thrylos.UTXO) []map[string]interface{} {
// 	result := make([]map[string]interface{}, len(inputs))
// 	for i, input := range inputs {
// 		result[i] = map[string]interface{}{
// 			"amount":        input.Amount,
// 			"index":         int(input.Index),
// 			"owner_address": input.OwnerAddress,
// 		}
// 	}
// 	return result
// }

// func convertOutputsToJSON(outputs []*thrylos.UTXO) []map[string]interface{} {
// 	result := make([]map[string]interface{}, len(outputs))
// 	for i, output := range outputs {
// 		result[i] = map[string]interface{}{
// 			"amount":        output.Amount,
// 			"index":         int(output.Index),
// 			"owner_address": output.OwnerAddress,
// 		}
// 	}
// 	return result
// }

// // ConvertSharedToThrylos converts a shared.Transaction to a thrylos.Transaction.
// func ConvertSharedToThrylos(tx *Transaction) (*thrylos.Transaction, error) {
// 	if tx == nil {
// 		return nil, nil // If the transaction is nil, return no error and no transaction.
// 	}

// 	protoInputs := make([]*thrylos.UTXO, len(tx.Inputs))
// 	for i, input := range tx.Inputs {
// 		protoInputs[i] = &thrylos.UTXO{
// 			TransactionId: input.TransactionID,
// 			Index:         int32(input.Index), // Assuming conversion to int32 is needed.
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        int64(input.Amount), // Assuming conversion to int64 is needed.
// 		}
// 	}

// 	protoOutputs := make([]*thrylos.UTXO, len(tx.Outputs))
// 	for i, output := range tx.Outputs {
// 		protoOutputs[i] = &thrylos.UTXO{
// 			TransactionId: output.TransactionID,
// 			Index:         int32(output.Index), // Assuming conversion to int32 is needed.
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount), // Assuming conversion to int64 is needed.
// 		}
// 	}

// 	// Decode the base64-encoded signature
// 	signatureBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decode signature: %v", err)
// 	}

// 	return &thrylos.Transaction{
// 		Id:        tx.ID,
// 		Timestamp: tx.Timestamp,
// 		Inputs:    protoInputs,
// 		Outputs:   protoOutputs,
// 		Signature: signatureBytes, // Use the decoded byte slice here
// 	}, nil
// }

// // GenerateTransactionID creates a unique identifier for a transaction based on its contents.
// func GenerateTransactionID(inputs []UTXO, outputs []UTXO, address string, amount, gasFee int) (string, error) {
// 	var builder strings.Builder

// 	// Append the sender's address
// 	builder.WriteString(address)

// 	// Append the amount and gas fee
// 	builder.WriteString(fmt.Sprintf("%d%d", amount, gasFee))

// 	// Append details of inputs and outputs
// 	for _, input := range inputs {
// 		builder.WriteString(fmt.Sprintf("%s%d", input.OwnerAddress, input.Amount))
// 	}
// 	for _, output := range outputs {
// 		builder.WriteString(fmt.Sprintf("%s%d", output.OwnerAddress, output.Amount))
// 	}

// 	// Use the cachedHashData function to get the hash of the builder's string
// 	hashBytes := cachedHashData([]byte(builder.String()))
// 	return hex.EncodeToString(hashBytes), nil
// }

// // SanitizeAndFormatAddress cleans and validates blockchain addresses.
// func SanitizeAndFormatAddress(address string) (string, error) {
// 	// Trim any leading/trailing whitespace
// 	address = strings.TrimSpace(address)

// 	// Check if the address starts with the correct prefix
// 	if !strings.HasPrefix(address, "tl1") {
// 		return "", fmt.Errorf("invalid address: must start with 'tl1'")
// 	}

// 	// Attempt to decode the Bech32 address
// 	_, decoded, err := bech32.Decode(address)
// 	if err != nil {
// 		return "", fmt.Errorf("invalid Bech32 address: %v", err)
// 	}

// 	// Re-encode to ensure it's in the canonical format
// 	reencoded, err := bech32.Encode("tl1", decoded)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to re-encode address: %v", err)
// 	}

// 	return reencoded, nil
// }

// type TransactionForSigning struct {
// 	ID               string   `json:"id"`
// 	Timestamp        int64    `json:"timestamp"`
// 	Inputs           []UTXO   `json:"inputs"`
// 	Outputs          []UTXO   `json:"outputs"`
// 	EncryptedInputs  []byte   `json:"encryptedInputs,omitempty"`
// 	EncryptedOutputs []byte   `json:"encryptedOutputs,omitempty"`
// 	EncryptedAESKey  []byte   `json:"encryptedAESKey,omitempty"`
// 	PreviousTxIds    []string `json:"previousTxIds,omitempty"`
// 	Sender           string   `json:"sender"`
// 	GasFee           int      `json:"gasFee"`
// }

// func SerializeTransactionForSigning(tx *Transaction) ([]byte, error) {
// 	txForSigning := TransactionForSigning{
// 		ID:               tx.ID,
// 		Timestamp:        tx.Timestamp,
// 		Inputs:           tx.Inputs,
// 		Outputs:          tx.Outputs,
// 		EncryptedInputs:  tx.EncryptedInputs,
// 		EncryptedOutputs: tx.EncryptedOutputs,
// 		EncryptedAESKey:  tx.EncryptedAESKey,
// 		PreviousTxIds:    tx.PreviousTxIds,
// 		Sender:           tx.Sender,
// 		GasFee:           tx.GasFee,
// 	}
// 	return json.Marshal(txForSigning)
// }

// func deriveAddressFromPublicKey(publicKey *mldsa44.PublicKey) (string, error) {
// 	// Get the public key bytes
// 	publicKeyBytes := publicKey.Bytes()

// 	// Convert public key bytes to 5-bit words for bech32 encoding
// 	words, err := bech32.ConvertBits(publicKeyBytes, 8, 5, true)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to convert public key to 5-bit words: %v", err)
// 	}

// 	// Encode with your tl1 prefix (matching your frontend)
// 	address, err := bech32.Encode("tl1", words)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to encode bech32 address: %v", err)
// 	}

// 	return address, nil
// }

// func ValidateAndConvertTransaction(
// 	tx *thrylos.Transaction,
// 	db BlockchainDBInterface,
// 	publicKey *mldsa44.PublicKey,
// 	estimator GasEstimator,
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
// 	sharedTx, err := ConvertThrylosTransactionToLocal(tx)
// 	if err != nil {
// 		return fmt.Errorf("failed to convert transaction to shared type: %v", err)
// 	}

// 	if err := validateInputsAndOutputs(&sharedTx); err != nil {
// 		return fmt.Errorf("invalid transaction: %v", err)
// 	}

// 	return nil
// }

// func createExactCanonicalForm(tx *thrylos.Transaction) map[string]interface{} {
// 	inputs := make([]map[string]interface{}, len(tx.Inputs))
// 	for i, input := range tx.Inputs {
// 		inputs[i] = map[string]interface{}{
// 			"amount": input.Amount,
// 			"index":  input.Index,
// 		}
// 	}

// 	outputs := make([]map[string]interface{}, len(tx.Outputs))
// 	for i, output := range tx.Outputs {
// 		outputs[i] = map[string]interface{}{
// 			"amount": output.Amount,
// 			"index":  output.Index,
// 		}
// 	}

// 	return map[string]interface{}{
// 		"gasfee":          tx.Gasfee,
// 		"id":              tx.Id,
// 		"inputs":          inputs,
// 		"outputs":         outputs,
// 		"previous_tx_ids": tx.PreviousTxIds,
// 		"sender":          tx.Sender,
// 		"status":          "pending",
// 		"timestamp":       tx.Timestamp,
// 	}
// }

// // Additional helper functions for converting between types
// func UTXOToMap(utxo *UTXO) map[string]interface{} {
// 	return map[string]interface{}{
// 		"TransactionID": utxo.TransactionID,
// 		"Index":         utxo.Index,
// 		"OwnerAddress":  utxo.OwnerAddress,
// 		"Amount":        utxo.Amount,
// 		"IsSpent":       utxo.IsSpent,
// 	}
// }

// func UTXOsToMapSlice(utxos []*UTXO) []map[string]interface{} {
// 	result := make([]map[string]interface{}, len(utxos))
// 	for i, utxo := range utxos {
// 		result[i] = UTXOToMap(utxo)
// 	}
// 	return result
// }
// func validateInputsAndOutputs(tx *Transaction) error {
// 	if tx.Sender == "" {
// 		return fmt.Errorf("transaction sender is empty")
// 	}

// 	if len(tx.Inputs) == 0 {
// 		return fmt.Errorf("transaction has no inputs")
// 	}
// 	if len(tx.Outputs) == 0 {
// 		return fmt.Errorf("transaction has no outputs")
// 	}

// 	// Validate that all inputs belong to sender
// 	for _, input := range tx.Inputs {
// 		if input.OwnerAddress != tx.Sender {
// 			return fmt.Errorf("input address %s does not match sender %s",
// 				input.OwnerAddress, tx.Sender)
// 		}
// 	}

// 	var inputSum, outputSum int64

// 	// Validate inputs (in nanoTHRYLOS)
// 	for _, input := range tx.Inputs {
// 		if input.Amount <= 0 {
// 			return fmt.Errorf("invalid input amount: %d nanoTHRYLOS", input.Amount)
// 		}
// 		inputSum += input.Amount
// 	}

// 	// Validate outputs (in nanoTHRYLOS)
// 	for _, output := range tx.Outputs {
// 		if output.Amount <= 0 {
// 			return fmt.Errorf("invalid output amount: %d nanoTHRYLOS", output.Amount)
// 		}
// 		outputSum += output.Amount
// 	}

// 	// Convert gas fee to int64 to ensure type consistency
// 	gasFeeNano := int64(tx.GasFee)

// 	log.Printf("Transaction validation - Input sum: %d nanoTHRYLOS (%.7f THRYLOS)", inputSum, float64(inputSum)/1e7)
// 	log.Printf("Transaction validation - Output sum: %d nanoTHRYLOS (%.7f THRYLOS)", outputSum, float64(outputSum)/1e7)
// 	log.Printf("Transaction validation - Gas fee: %d nanoTHRYLOS (%.7f THRYLOS)", gasFeeNano, float64(gasFeeNano)/1e7)
// 	log.Printf("Transaction validation - Total (outputs + gas fee): %d nanoTHRYLOS (%.7f THRYLOS)", outputSum+gasFeeNano, float64(outputSum+gasFeeNano)/1e7)

// 	// Account for gas fee in the balance calculation using integer arithmetic
// 	if inputSum != outputSum+gasFeeNano {
// 		return fmt.Errorf("inputs (%d nanoTHRYLOS) do not match outputs (%d nanoTHRYLOS) plus gas fee (%d nanoTHRYLOS)",
// 			inputSum, outputSum, gasFeeNano)
// 	}

// 	return nil
// }
