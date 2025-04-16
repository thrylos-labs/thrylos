package network

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	canonicaljson "github.com/gibson042/canonicaljson-go" // For canonical signing payload
	"github.com/google/uuid"                              // <<< Added Import
	"github.com/thrylos-labs/thrylos/crypto"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

// Handler struct now contains a messageBus instead of a direct node reference
type Handler struct {
	messageBus types.MessageBusInterface
}

// --- START: Canonical Serialization Logic ---

// Define a struct specifically for signing, ensuring deterministic fields
type TransactionSigningPayload struct {
	ID              string               `json:"id"`
	Timestamp       int64                `json:"timestamp"`
	SenderAddress   string               `json:"senderAddress"` // Use string representation
	GasFee          int                  `json:"gasFee"`
	SenderPublicKey string               `json:"senderPublicKey"` // Base64 encoded PK
	Inputs          []UTXOSigningPayload `json:"inputs"`
	Outputs         []UTXOSigningPayload `json:"outputs"`
	// Add any other fields that MUST be covered by the signature (e.g., Nonce, NetworkID)
}

type UTXOSigningPayload struct {
	TransactionID string `json:"transactionId"`
	Index         int    `json:"index"`
	OwnerAddress  string `json:"ownerAddress"` // Use string representation
	Amount        int64  `json:"amount"`       // Use int64 directly
}

// SerializeTransactionForSigning creates the canonical byte representation for signing.
// It takes the backend-constructed transaction and prepares it for the client to sign.
func SerializeTransactionForSigning(tx *types.Transaction) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("cannot serialize nil transaction")
	}

	// Check if SenderAddress is the zero value for its type
	if tx.SenderAddress == (address.Address{}) { // <<< CORRECTED CHECK
		return nil, fmt.Errorf("cannot serialize transaction with uninitialized sender address")
	}
	if tx.SenderPublicKey == nil {
		return nil, fmt.Errorf("cannot serialize transaction with nil sender public key")
	}
	// ID and Timestamp should likely be non-zero/non-empty as well
	if tx.ID == "" {
		return nil, fmt.Errorf("transaction ID cannot be empty for signing payload")
	}
	if tx.Timestamp == 0 {
		return nil, fmt.Errorf("transaction timestamp cannot be zero for signing payload")
	}

	// Convert SenderPublicKey to base64 string
	// Ensure your crypto.PublicKey interface has Marshal() or Bytes()
	pubKeyBytes, err := tx.SenderPublicKey.Marshal() // Or .Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sender public key for signing payload: %v", err)
	}
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("marshalled sender public key is empty")
	}
	pubKeyString := base64.StdEncoding.EncodeToString(pubKeyBytes)

	payload := TransactionSigningPayload{
		ID:              tx.ID,
		Timestamp:       tx.Timestamp,
		SenderAddress:   tx.SenderAddress.String(),
		GasFee:          tx.GasFee,
		SenderPublicKey: pubKeyString,
		Inputs:          make([]UTXOSigningPayload, len(tx.Inputs)),
		Outputs:         make([]UTXOSigningPayload, len(tx.Outputs)),
	}

	// Convert Inputs (ensure types.UTXO has these fields)
	for i, input := range tx.Inputs {
		// Assuming input.OwnerAddress is string; if it's address.Address, use .String()
		ownerAddrStr := input.OwnerAddress
		// if addrObj, ok := input.OwnerAddress.(address.Address); ok { // Example if it was address.Address type
		// 	ownerAddrStr = addrObj.String()
		// } else if strAddr, ok := input.OwnerAddress.(string); ok {
		//  ownerAddrStr = strAddr
		// } else {
		//  return nil, fmt.Errorf("invalid type for input %d owner address", i)
		// }

		payload.Inputs[i] = UTXOSigningPayload{
			TransactionID: input.TransactionID, // Should be present for inputs
			Index:         input.Index,
			OwnerAddress:  ownerAddrStr,        // Use the determined string address
			Amount:        int64(input.Amount), // Assuming types.Amount is int64 or convertible
		}
	}

	// Convert Outputs (ensure types.UTXO has these fields)
	for i, output := range tx.Outputs {
		// Assuming output.OwnerAddress is string
		ownerAddrStr := output.OwnerAddress
		// Similar type check as above if needed

		payload.Outputs[i] = UTXOSigningPayload{
			// TransactionID might be empty for new outputs, that's okay
			TransactionID: output.TransactionID,
			Index:         output.Index,
			OwnerAddress:  ownerAddrStr,
			Amount:        int64(output.Amount),
		}
	}

	// --- Deterministic Sorting (CRUCIAL for Canonicalization) ---
	// Sort Inputs by TransactionID then Index
	sort.SliceStable(payload.Inputs, func(i, j int) bool {
		if payload.Inputs[i].TransactionID != payload.Inputs[j].TransactionID {
			return payload.Inputs[i].TransactionID < payload.Inputs[j].TransactionID
		}
		return payload.Inputs[i].Index < payload.Inputs[j].Index
	})
	// Sort Outputs by Index (assuming index is unique and sequential 0, 1, ...)
	sort.SliceStable(payload.Outputs, func(i, j int) bool {
		return payload.Outputs[i].Index < payload.Outputs[j].Index
	})

	// Serialize using canonical JSON
	canonicalBytes, err := canonicaljson.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction payload canonically: %v", err)
	}

	// Log the canonical string for debugging verification on frontend/backend
	// log.Printf("DEBUG: Canonical Payload for Signing (TxID: %s): %s", tx.ID, string(canonicalBytes))

	return canonicalBytes, nil
}

// NewHandler creates a new Handler with the message bus
func NewHandler(messageBus types.MessageBusInterface) *Handler {
	return &Handler{messageBus: messageBus}
}

func sendJSONRPCError(w http.ResponseWriter, jsonrpcErr *JSONRPCError, id interface{}) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		Error:   jsonrpcErr,
		ID:      id,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)
}

type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Main JSON-RPC handler that routes to appropriate handlers
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32700,
			Message: "Parse error",
		}, req.ID)
		return
	}

	var result interface{}
	var err error

	// REMEMBER THIS

	//  addresses aren't "registered" in the traditional sense. They simply exist
	//  once they're generated by a wallet, and they become
	//vVisible on the blockchain only when they're involved in transactions.

	// Check other JSON-RPC methods to make sure they're working as expected
	// Improve error handling to gracefully manage any future connection issues
	// Add features that utilize the blockchain data you're now able to retrieve

	// Only include core handlers
	switch req.Method {
	case "fundNewAddress":
		result, err = h.handleFundNewAddress(req.Params)
	case "getBalance":
		// - Check wallet balances
		result, err = h.handleGetBalance(req.Params)
	case "getUTXO":
		// Get transaction inputs for creating new transactions
		result, err = h.handleGetUTXO(req.Params)
	case "getBlock":
		//  - Get block details
		result, err = h.handleGetBlock(req.Params)
	case "getBlockchainInfo":
		//  - Get high-level blockchain information
		result, err = h.handleGetBlockchainInfo(req.Params)
	case "getBlockTransactions":
		// - Get transactions in a block
		result, err = h.handleGetBlockTransactions(req.Params)
	case "prepareTransaction": // NEW
		result, err = h.handlePrepareTransaction(req.Params)
	case "submitSignedTransaction":
		//  - Send transactions
		result, err = h.handleSubmitSignedTransaction(req.Params)
	case "estimateGas":
		// - Calculate transaction fees
		result, err = h.handleEstimateGas(req.Params)
	case "stake":
		//  Main entry point for staking actions
		result, err = h.handleStaking(req.Params)
	case "getStakingInfo":
		// - Get staking status information
		result, err = h.handleGetStakingInfo(req.Params)
	default:
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32601,
			Message: "Method not found",
		}, req.ID)
		return
	}

	if err != nil {
		sendJSONRPCError(w, &JSONRPCError{
			Code:    -32603,
			Message: err.Error(),
		}, req.ID)
		return
	}

	response := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleGetBalance(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	address, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid address parameter")
	}

	// First try the direct stakeholders lookup
	stakeholderCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetStakeholderBalance,
		Data:       address,
		ResponseCh: stakeholderCh,
	})

	// Wait for response
	stakeholderResp := <-stakeholderCh
	if stakeholderResp.Error == nil {
		if balance, ok := stakeholderResp.Data.(int64); ok {
			log.Printf("Found balance from stakeholders map for %s: %d", address, balance)
			return struct {
				Balance        int64   `json:"balance"`
				BalanceThrylos float64 `json:"balanceThrylos"`
			}{
				Balance:        balance,
				BalanceThrylos: float64(balance) / 1e7,
			}, nil
		}
	}

	// Fallback to original UTXO-based balance lookup
	responseCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetBalance,
		Data:       address,
		ResponseCh: responseCh,
	})

	// Wait for response
	response := <-responseCh
	log.Printf("DEBUG: handleGetBalance network handler received response: %+v", response)

	if response.Error != nil {
		log.Printf("Error getting balance for address %s: %v", address, response.Error)
		return struct {
			Balance        int64   `json:"balance"`
			BalanceThrylos float64 `json:"balanceThrylos"`
		}{
			Balance:        0,
			BalanceThrylos: 0,
		}, nil
	}

	balance, ok := response.Data.(int64)
	if !ok {
		return nil, fmt.Errorf("invalid balance data type")
	}

	return struct {
		Balance        int64   `json:"balance"`
		BalanceThrylos float64 `json:"balanceThrylos"`
	}{
		Balance:        balance,
		BalanceThrylos: float64(balance) / 1e7,
	}, nil
}

// Fund addresses from the genesis account or can it fund the address from the balance?

// Add this method to your Handler struct in Go
func (h *Handler) handleFundNewAddress(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	address, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid address parameter")
	}

	// Default amount: 70 THRYLOS in nano
	amountInt64 := int64(700000000)

	// If amount is specified as a second parameter, use that instead
	if len(params) > 1 {
		if amountParam, ok := params[1].(float64); ok {
			amountInt64 = int64(amountParam)
		}
	}

	// Convert int64 to amount.Amount
	// Using simple type casting since amount.Amount is a type alias for int64
	amountValue := amount.Amount(amountInt64)

	// Create response channel
	responseCh := make(chan types.Response)

	// Send message to fund new address
	h.messageBus.Publish(types.Message{
		Type: types.FundNewAddress,
		Data: types.FundAddressRequest{
			Address: address,
			Amount:  amountValue,
		},
		ResponseCh: responseCh,
	})

	// Wait for response
	response := <-responseCh
	if response.Error != nil {
		return nil, fmt.Errorf("error funding address: %v", response.Error)
	}

	return map[string]interface{}{
		"status":  "funded",
		"message": fmt.Sprintf("Address %s has been funded with %0.2f THRYLOS", address, float64(amountValue)/1e7),
		"amount":  float64(amountValue) / 1e7,
	}, nil
}

// handleGetUTXO now uses message bus
func (h *Handler) handleGetUTXO(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	address, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid address parameter")
	}

	log.Printf("Fetching UTXOs for address: %s", address)

	// Create response channel
	responseCh := make(chan types.Response)

	// Send message to get UTXOs
	h.messageBus.Publish(types.Message{
		Type: types.GetUTXOs,
		Data: types.UTXORequest{
			Address: address,
		},
		ResponseCh: responseCh,
	})

	// Wait for response
	response := <-responseCh

	if response.Error != nil {
		log.Printf("Error fetching UTXOs for address %s: %v", address, response.Error)
		return nil, fmt.Errorf("error fetching UTXOs: %v", response.Error)
	}

	// Convert response data to UTXOs
	utxos, ok := response.Data.([]types.UTXO)
	if !ok {
		return nil, fmt.Errorf("invalid UTXOs data type")
	}

	if len(utxos) == 0 {
		log.Printf("No UTXOs found for address: %s", address)
		return []interface{}{}, nil // Empty array instead of error for JSON-RPC
	}

	// Log UTXOs for debugging
	for i, utxo := range utxos {
		log.Printf("UTXO %d for address %s: {ID: %s, TransactionID: %s, Index: %d, Amount: %d, IsSpent: %v}",
			i, address, utxo.ID, utxo.TransactionID, utxo.Index, utxo.Amount, utxo.IsSpent)
	}

	return utxos, nil
}

// Add this method to your Handler struct in the network package

// handleGetBlock handles JSON-RPC requests to get block information
// Add this method to your Handler struct in the network package

// handleGetBlock handles JSON-RPC requests to get block information
func (h *Handler) handleGetBlock(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("block identifier required")
	}

	// Create response channel
	responseCh := make(chan types.Response)

	// Handle both string (hash) and number (height) parameters
	var messageData interface{}
	switch v := params[0].(type) {
	case string:
		messageData = v // block hash
	case float64:
		messageData = int32(v) // block height
	default:
		return nil, fmt.Errorf("invalid block identifier type")
	}

	// Send message to get block using ProcessBlock message type
	h.messageBus.Publish(types.Message{
		Type:       types.ProcessBlock, // Use existing ProcessBlock type
		Data:       messageData,
		ResponseCh: responseCh,
	})

	// Wait for response
	response := <-responseCh

	if response.Error != nil {
		return nil, fmt.Errorf("block not found: %v", response.Error)
	}

	// Convert response data to Block
	block, ok := response.Data.(*types.Block)
	if !ok {
		return nil, fmt.Errorf("invalid block data type")
	}

	if block.Transactions == nil {
		log.Printf("No transactions found in block %v", params[0])
	}

	return block, nil
}

// handleGetBlock now uses message bus
func (h *Handler) handleGetBlockchainInfo(params []interface{}) (interface{}, error) {
	// Create a single response channel
	infoCh := make(chan types.Response)

	// Request all blockchain info at once
	h.messageBus.Publish(types.Message{
		Type:       types.GetBlockchainInfo,
		Data:       nil, // No specific data needed
		ResponseCh: infoCh,
	})

	// Wait for response with timeout
	select {
	case resp := <-infoCh:
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Data, nil
	case <-time.After(5 * time.Second):
		return map[string]interface{}{
			"height":      0,
			"chainId":     "thrylos-testnet",
			"lastBlock":   "",
			"nodeCount":   0,
			"nodeVersion": "1.0.0",
			"isSyncing":   false,
		}, fmt.Errorf("timeout waiting for blockchain info")
	}
}

func (h *Handler) handleGetBlockTransactions(params []interface{}) (interface{}, error) {
	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("block ID parameter required")
	}

	// Extract blockID from params
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	blockID, ok := reqData["blockId"].(string)
	if !ok {
		return nil, fmt.Errorf("blockId required")
	}

	// Create response channel
	blockCh := make(chan types.Response)

	// Send message to get block
	h.messageBus.Publish(types.Message{
		Type:       types.ProcessBlock,
		Data:       blockID,
		ResponseCh: blockCh,
	})

	// Wait for response
	blockResp := <-blockCh

	if blockResp.Error != nil {
		return nil, fmt.Errorf("block not found: %v", blockResp.Error)
	}

	// Convert response data to Block
	block, ok := blockResp.Data.(*types.Block)
	if !ok {
		return nil, fmt.Errorf("invalid block data type")
	}

	// Return transactions with additional metadata
	return map[string]interface{}{
		"blockId":          blockID,
		"transactionCount": len(block.Transactions),
		"transactions":     block.Transactions,
	}, nil
}

func (h *Handler) handlePrepareTransaction(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters object required")
	}
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid parameters format, expected JSON object")
	}

	// --- Extract Input Parameters ---
	sender, ok := reqData["sender"].(string)
	if !ok || sender == "" {
		return nil, fmt.Errorf("missing or invalid 'sender' address")
	}
	recipientAddress, ok := reqData["recipient"].(string)
	if !ok || recipientAddress == "" {
		return nil, fmt.Errorf("missing or invalid 'recipient' address")
	}
	amountNanoFloat, ok := reqData["amountNano"].(float64) // Amount in nano units
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'amountNano'")
	}
	amountToSendNano := int64(amountNanoFloat)
	publicKeyString, ok := reqData["publicKey"].(string) // Sender's public key (base64) - REQUIRED
	if !ok || publicKeyString == "" {
		return nil, fmt.Errorf("missing or invalid 'publicKey'")
	}
	suggestedGasFeeFloat, hasSuggestedFee := reqData["gasFee"].(float64)

	// --- Basic Validations ---
	if amountToSendNano <= 0 {
		return nil, fmt.Errorf("transaction amount must be positive")
	}
	// Consider adding address format validation here if needed using address.FromString

	// --- Decode Sender Public Key & Verify Address Match ---
	senderPubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %v", err)
	}
	senderPubKey, err := crypto.NewPublicKeyFromBytes(senderPubKeyBytes) // Returns crypto.PublicKey interface
	if err != nil {
		return nil, fmt.Errorf("failed to create public key object from bytes: %v", err)
	}
	if senderPubKey == nil {
		return nil, fmt.Errorf("failed to reconstruct sender public key (nil result)")
	}

	// --- Derive address USING the interface method ---
	// The previous compiler error guaranteed senderPubKey has an Address() method.
	derivedAddrObject, err := senderPubKey.Address() // Call the method required by the crypto.PublicKey interface
	if err != nil {
		// Handle error if the Address() method itself can fail
		log.Printf("ERROR: [Prepare] Failed to derive address using public key's Address() method: %v", err)
		return nil, fmt.Errorf("failed to derive address using public key's Address() method: %v", err)
	}

	// Convert the resulting address object (likely address.Address type) to string for comparison
	// Ensure the object returned by Address() has a String() method
	derivedSenderAddrString := derivedAddrObject.String()
	// --- End Address Derivation ---

	// --- Perform the check ---
	if derivedSenderAddrString != sender {
		return nil, fmt.Errorf("sender address %s does not match provided public key (derived %s)", sender, derivedSenderAddrString)
	}
	log.Printf("INFO: [Prepare] Sender address successfully verified against public key.")

	// --- Determine Gas Fee ---
	// Ensure config constants are exported (uppercase) and package is imported
	gasFee := int(config.DefaultGasFee)
	if hasSuggestedFee {
		gasFee = int(suggestedGasFeeFloat)
		if gasFee < config.MinGasFee {
			log.Printf("WARN: Suggested gas fee %d below minimum %d, using minimum.", gasFee, config.MinGasFee)
			gasFee = config.MinGasFee
		}
	}

	amountNeeded := amountToSendNano + int64(gasFee)

	// --- Fetch Sender's UTXOs (Add timeout) ---
	log.Printf("INFO: [Prepare] Fetching UTXOs for sender %s", sender)
	utxoResponseCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetUTXOs,
		Data:       types.UTXORequest{Address: sender},
		ResponseCh: utxoResponseCh,
	})

	var utxoResponse types.Response
	select {
	case utxoResponse = <-utxoResponseCh:
		if utxoResponse.Error != nil {
			log.Printf("ERROR: [Prepare] Failed to fetch UTXOs for %s: %v", sender, utxoResponse.Error)
			return nil, fmt.Errorf("failed to fetch UTXOs: %v", utxoResponse.Error)
		}
	case <-time.After(5 * time.Second): // Timeout
		log.Printf("ERROR: [Prepare] Timeout fetching UTXOs for %s", sender)
		return nil, fmt.Errorf("timeout fetching UTXOs")
	}

	availableUTXOs, ok := utxoResponse.Data.([]types.UTXO)
	if !ok {
		log.Printf("ERROR: [Prepare] Invalid UTXO data type received for %s", sender)
		return nil, fmt.Errorf("invalid UTXO data type received")
	}
	log.Printf("INFO: [Prepare] Found %d UTXOs for sender %s", len(availableUTXOs), sender)

	// --- UTXO Selection (With deterministic sorting) ---
	var selectedUTXOs []types.UTXO
	var selectedTotal int64 = 0

	unspentUTXOs := make([]types.UTXO, 0, len(availableUTXOs))
	for _, utxo := range availableUTXOs {
		if !utxo.IsSpent {
			unspentUTXOs = append(unspentUTXOs, utxo)
		}
	}

	sort.SliceStable(unspentUTXOs, func(i, j int) bool {
		if unspentUTXOs[i].Amount != unspentUTXOs[j].Amount {
			return unspentUTXOs[i].Amount < unspentUTXOs[j].Amount
		}
		if unspentUTXOs[i].TransactionID != unspentUTXOs[j].TransactionID {
			return unspentUTXOs[i].TransactionID < unspentUTXOs[j].TransactionID
		}
		return unspentUTXOs[i].Index < unspentUTXOs[j].Index
	})

	for _, utxo := range unspentUTXOs {
		selectedUTXOs = append(selectedUTXOs, utxo)
		selectedTotal += int64(utxo.Amount)
		if selectedTotal >= amountNeeded {
			break
		}
	}

	if selectedTotal < amountNeeded {
		log.Printf("ERROR: [Prepare] Insufficient funds for %s. Needed: %d, Available in UTXOs: %d", sender, amountNeeded, selectedTotal)
		return nil, fmt.Errorf("insufficient funds. Needed %d nanoTHR, have %d nanoTHR in available UTXOs", amountNeeded, selectedTotal)
	}
	log.Printf("INFO: [Prepare] Selected %d UTXOs with total value %d for amount %d + fee %d", len(selectedUTXOs), selectedTotal, amountToSendNano, gasFee)

	// --- Calculate Change ---
	changeAmount := selectedTotal - amountNeeded
	log.Printf("INFO: [Prepare] Calculated change: %d nanoTHR", changeAmount)

	// --- Construct the *Prepared* Transaction Data ---
	txID := "tx-" + uuid.NewString()
	senderAddr, err := address.FromString(sender) // Convert sender string to address.Address type
	if err != nil {
		// This check should ideally be done earlier after extracting 'sender'
		log.Printf("ERROR: [Prepare] Failed to parse sender address string '%s': %v", sender, err)
		return nil, fmt.Errorf("invalid sender address format: %v", err)
	}

	preparedTxData := types.Transaction{
		ID:              txID,
		Timestamp:       time.Now().UnixNano() / int64(time.Millisecond), // Milliseconds timestamp
		SenderAddress:   *senderAddr,                                     // Use the parsed address object
		GasFee:          gasFee,
		SenderPublicKey: senderPubKey, // Assign the crypto.PublicKey interface object
		Inputs:          selectedUTXOs,
		Outputs:         []types.UTXO{},
	}

	// Add Recipient Output
	// Ensure recipientAddress is validated if necessary (e.g., using address.FromString)
	preparedTxData.Outputs = append(preparedTxData.Outputs, types.UTXO{
		OwnerAddress: recipientAddress, // Assuming string address type is correct for types.UTXO
		Amount:       amount.Amount(amountToSendNano),
		Index:        0,
	})
	// Add Change Output
	if changeAmount > 0 {
		preparedTxData.Outputs = append(preparedTxData.Outputs, types.UTXO{
			OwnerAddress: sender, // Change goes back to sender (string representation is ok here per type?)
			Amount:       amount.Amount(changeAmount),
			Index:        1,
		})
	}

	// --- Generate Canonical Payload String ---
	canonicalPayloadBytes, err := SerializeTransactionForSigning(&preparedTxData)
	if err != nil {
		log.Printf("ERROR: [Prepare] Failed to serialize prepared transaction %s: %v", txID, err)
		return nil, fmt.Errorf("failed to serialize transaction for signing: %v", err)
	}
	canonicalPayloadString := base64.StdEncoding.EncodeToString(canonicalPayloadBytes)

	log.Printf("INFO: [Prepare] Prepared transaction %s successfully.", txID)

	// --- Return the payload to be signed ---
	return struct {
		TxID                   string `json:"txId"`
		CanonicalPayloadString string `json:"canonicalPayloadString"` // Base64 encoded
		Message                string `json:"message"`
	}{
		TxID:                   txID,
		CanonicalPayloadString: canonicalPayloadString,
		Message:                "Transaction prepared. Please sign the canonicalPayloadString and submit.",
	}, nil
}

const MinTransactionAmount int64 = 1 * config.NanoPerThrylos // 1 THRYLOS in nanoTHRYLOS

func (h *Handler) handleSubmitSignedTransaction(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters object required")
	}
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format, expected JSON object")
	}

	// --- Extract Required Fields ---
	txId, ok := reqData["txId"].(string)
	if !ok || txId == "" {
		return nil, fmt.Errorf("missing or invalid 'txId'")
	}
	signatureString, ok := reqData["signature"].(string)
	if !ok || signatureString == "" {
		return nil, fmt.Errorf("invalid or missing 'signature' string")
	}
	publicKeyString, ok := reqData["publicKey"].(string)
	if !ok || publicKeyString == "" {
		return nil, fmt.Errorf("invalid or missing 'publicKey' string")
	}
	canonicalPayloadString, ok := reqData["canonicalPayloadString"].(string)
	if !ok || canonicalPayloadString == "" {
		return nil, fmt.Errorf("invalid or missing 'canonicalPayloadString'")
	}

	// --- Validation Goroutine ---
	type validationResult struct {
		ValidatedTx *types.Transaction // The deserialized, validated transaction structure
		Err         error
	}
	validationDone := make(chan validationResult, 1)

	go func() {
		var vr validationResult // Result to send back

		// --- Decode Inputs ---
		var publicKeyBytes []byte
		publicKeyBytes, vr.Err = base64.StdEncoding.DecodeString(publicKeyString)
		if vr.Err != nil {
			vr.Err = fmt.Errorf("invalid public key encoding: %v", vr.Err)
			validationDone <- vr
			return
		}

		var signatureBytes []byte // Store decoded signature temporarily
		signatureBytes, vr.Err = base64.StdEncoding.DecodeString(signatureString)
		if vr.Err != nil {
			vr.Err = fmt.Errorf("invalid signature encoding: %v", vr.Err)
			validationDone <- vr
			return
		}
		if len(signatureBytes) != mldsa44.SignatureSize {
			log.Printf("TX_VALIDATE_ERROR: Sig size mismatch: got %d, want %d", len(signatureBytes), mldsa44.SignatureSize)
			vr.Err = fmt.Errorf("decoded signature has incorrect size")
			validationDone <- vr
			return
		}

		canonicalPayloadBytes, err := base64.StdEncoding.DecodeString(canonicalPayloadString)
		if err != nil {
			vr.Err = fmt.Errorf("invalid canonicalPayloadString encoding: %v", err)
			validationDone <- vr
			return
		}

		// --- Unmarshal Public Key (for Verification) ---
		pk := new(mldsa44.PublicKey)
		if vr.Err = pk.UnmarshalBinary(publicKeyBytes); vr.Err != nil {
			vr.Err = fmt.Errorf("failed to unmarshal public key for verification: %v", vr.Err)
			validationDone <- vr
			return
		}

		// --- Verify Signature against Canonical Payload ---
		log.Printf("TX_VALIDATE: Verifying signature for TxID %s against received canonical payload (len %d)", txId, len(canonicalPayloadBytes))
		ctxForVerify := []byte(nil)
		isValid := mldsa44.Verify(pk, canonicalPayloadBytes, ctxForVerify, signatureBytes)
		if !isValid {
			log.Printf("TX_VALIDATE_ERROR: Signature verification FAILED for TxID %s!", txId)
			vr.Err = fmt.Errorf("invalid signature")
			validationDone <- vr
			return
		}
		log.Printf("TX_VALIDATE_SUCCESS: Signature verified successfully for TxID %s!", txId)

		// --- Reconstruct our own PublicKey object (for Address Derivation & Tx Structure) ---
		senderPubKeyObj, err := crypto.NewPublicKeyFromBytes(publicKeyBytes)
		if err != nil {
			vr.Err = fmt.Errorf("failed to reconstruct PublicKey object: %v", err)
			validationDone <- vr
			return
		}
		if senderPubKeyObj == nil {
			vr.Err = fmt.Errorf("reconstructed PublicKey object is nil")
			validationDone <- vr
			return
		}

		// --- Deserialize Canonical Payload to check contents ---
		var signedPayload TransactionSigningPayload // Use the struct defined above
		if err := json.Unmarshal(canonicalPayloadBytes, &signedPayload); err != nil {
			vr.Err = fmt.Errorf("failed to unmarshal canonical payload string for validation: %v", err)
			validationDone <- vr
			return
		}

		// --- Sanity Checks on Deserialized Payload ---
		if signedPayload.ID != txId {
			log.Printf("TX_VALIDATE_ERROR: TxID mismatch! Claimed: %s, Inside Signed Payload: %s", txId, signedPayload.ID)
			vr.Err = fmt.Errorf("txId mismatch in signed payload")
			validationDone <- vr
			return
		}

		derivedAddrObject, err := senderPubKeyObj.Address()
		if err != nil {
			vr.Err = fmt.Errorf("failed to derive address post-validation using Address() method: %v", err)
			validationDone <- vr
			return
		}
		derivedAddressString := derivedAddrObject.String()

		if derivedAddressString != signedPayload.SenderAddress {
			log.Printf("TX_VALIDATE_ERROR: Address mismatch! Derived: %s, Signed Payload: %s", derivedAddressString, signedPayload.SenderAddress)
			vr.Err = fmt.Errorf("public key does not match sender address in signed payload")
			validationDone <- vr
			return
		}
		log.Printf("INFO: [Submit] Sender address verified against public key in signed payload.")

		if signedPayload.SenderPublicKey != publicKeyString {
			log.Printf("TX_VALIDATE_ERROR: Public key mismatch! Outside B64 != Inside B64")
			vr.Err = fmt.Errorf("public key mismatch in signed payload")
			validationDone <- vr
			return
		}

		// --- Reconstruct the final types.Transaction from the signed payload ---
		senderAddrFromPayload, err := address.FromString(signedPayload.SenderAddress)
		if err != nil {
			vr.Err = fmt.Errorf("failed to parse sender address '%s' from signed payload: %v", signedPayload.SenderAddress, err)
			validationDone <- vr
			return
		}

		// Create the types.Transaction object
		// Note: We use amount.Amount for GasFee and UTXO amounts internally now
		vr.ValidatedTx = &types.Transaction{
			ID:              signedPayload.ID,
			Timestamp:       signedPayload.Timestamp,
			SenderAddress:   *senderAddrFromPayload,
			GasFee:          int(signedPayload.GasFee), // Convert int64 payload value to int
			SenderPublicKey: senderPubKeyObj,
			Inputs:          make([]types.UTXO, len(signedPayload.Inputs)),
			Outputs:         make([]types.UTXO, len(signedPayload.Outputs)),
			Status:          "validated", // Mark as validated before adding to pool
			// Salt will be added by txPool.AddTransaction if needed
			// Signature is verified, not stored directly here
		}

		// Convert inputs from payload (assuming they are types.UTXO in the payload)
		for i, pInput := range signedPayload.Inputs { // pInput is UTXOSigningPayload
			if pInput.TransactionID == "" {
				vr.Err = fmt.Errorf("input %d missing transaction ID", i)
				validationDone <- vr
				return
			}
			// --- ** FIXES for Inputs ** ---
			vr.ValidatedTx.Inputs[i] = types.UTXO{
				TransactionID: pInput.TransactionID,
				Index:         pInput.Index,
				OwnerAddress:  pInput.OwnerAddress,          // Direct assignment: string -> string
				Amount:        amount.Amount(pInput.Amount), // Convert: int64 -> amount.Amount
				IsSpent:       false,
				// ID field is often contextual, assign if needed, otherwise omit
			}
			// --- ** END FIXES for Inputs ** ---
		}

		// Convert outputs from payload (assuming they are types.UTXO in the payload)
		for i, pOutput := range signedPayload.Outputs { // pOutput is UTXOSigningPayload
			if pOutput.OwnerAddress == "" {
				vr.Err = fmt.Errorf("output %d missing owner address", i)
				validationDone <- vr
				return
			}
			// --- ** FIXES for Outputs ** ---
			vr.ValidatedTx.Outputs[i] = types.UTXO{
				TransactionID: vr.ValidatedTx.ID,             // Output's TX ID is the current TX ID
				Index:         i,                             // Index of the output
				OwnerAddress:  pOutput.OwnerAddress,          // Direct assignment: string -> string
				Amount:        amount.Amount(pOutput.Amount), // Convert: int64 -> amount.Amount
				IsSpent:       false,                         // New outputs are not spent
				// ID field is often contextual, assign if needed, otherwise omit
			}
			// --- ** END FIXES for Outputs ** ---
		}

		vr.Err = nil // Indicate success
		validationDone <- vr
	}() // End of goroutine

	// --- Wait for Validation Result ---
	var validationRes validationResult
	select {
	case validationRes = <-validationDone:
		if validationRes.Err != nil {
			log.Printf("[Submit] Validation failed for TxID %s: %v", txId, validationRes.Err)
			return nil, validationRes.Err
		}
	case <-time.After(5 * time.Second):
		log.Printf("[Submit] Validation timeout occurred for TxID %s", txId)
		return nil, fmt.Errorf("validation timeout")
	}

	// --- Validation Successful ---
	log.Printf("[Submit] Validation completed successfully for TxID %s.", txId)
	validatedTx := validationRes.ValidatedTx // This is the *types.Transaction

	// --- *** CHANGE: Use Message Bus to Add Transaction to Pool *** ---
	log.Printf("[Submit] Sending transaction %s to Message Bus for addition to TxPool.", validatedTx.ID)

	// Create a response channel to hear back from the pool handler
	responseCh := make(chan types.Response, 1) // Buffered channel

	// Publish the message
	h.messageBus.Publish(types.Message{
		Type:       types.AddTransactionToPool,
		Data:       validatedTx, // Send the validated types.Transaction
		ResponseCh: responseCh,
	})

	// Wait for the response from the component handling AddTransactionToPool
	select {
	case resp := <-responseCh:
		if resp.Error != nil {
			log.Printf("ERROR: [Submit] Failed adding transaction %s to pool via message bus: %v", validatedTx.ID, resp.Error)
			// Return a user-friendly error
			return nil, fmt.Errorf("failed to submit transaction: %v", resp.Error)
		}
		// Success case from the message bus handler
		log.Printf("[Submit] Transaction %s successfully added to pool via message bus.", validatedTx.ID)
	case <-time.After(5 * time.Second): // Add a timeout
		log.Printf("ERROR: [Submit] Timeout waiting for TxPool add confirmation for transaction %s", validatedTx.ID)
		return nil, fmt.Errorf("timeout submitting transaction")
	}
	// --- *** END CHANGE *** ---

	// --- Return Success (Transaction Accepted by Pool Handler) ---
	log.Printf("[Submit] Successfully submitted transaction %s to pool.", validatedTx.ID)
	return struct {
		Message string `json:"message"`
		Status  string `json:"status"`
		TxID    string `json:"txId"`
	}{
		Message: fmt.Sprintf("Transaction %s submitted to pool successfully", validatedTx.ID),
		Status:  "pending", // Indicate it's pending in the pool
		TxID:    validatedTx.ID,
	}, nil
}

// Helper function to convert types.Transaction to *thrylos.Transaction (protobuf)
func convertToThrylosTransaction(tx *types.Transaction) *thrylos.Transaction {
	if tx == nil {
		log.Printf("ERROR: [convertToThrylosTransaction] called with nil input")
		return nil
	}

	senderStr := tx.SenderAddress.String()
	log.Printf("DEBUG: [convertToThrylosTransaction] Input tx.ID: %s, Sender: %q", tx.ID, senderStr)

	thrylosTx := &thrylos.Transaction{
		Id:        tx.ID,
		Sender:    senderStr,
		Timestamp: tx.Timestamp,
		Status:    "pending",
		Gasfee:    int32(tx.GasFee),
		// SenderPublicKey: tx.SenderPublicKey.Bytes(), // <<< REMOVE direct assignment here
	}

	// --- Handle SenderPublicKey Safely --- <<< ADD THIS BLOCK
	if tx.SenderPublicKey != nil {
		// Assuming crypto.PublicKey has a Marshal() method that returns []byte, error
		// Or a Bytes() method that returns []byte. Adjust accordingly.
		pubKeyBytes, err := tx.SenderPublicKey.Marshal() // Or .Bytes()
		if err != nil {
			// Log the error but maybe don't stop the whole conversion? Or return nil?
			log.Printf("ERROR: [convertToThrylosTransaction] Failed to marshal SenderPublicKey for tx %s: %v", tx.ID, err)
			// Depending on requirements, you might 'return nil' here if PK is essential
		} else if len(pubKeyBytes) > 0 {
			thrylosTx.SenderPublicKey = pubKeyBytes // Assign ONLY if not nil and marshaled ok
			log.Printf("DEBUG: [convertToThrylosTransaction] Assigned SenderPublicKey bytes (len %d)", len(pubKeyBytes))
		} else {
			log.Printf("WARN: [convertToThrylosTransaction] SenderPublicKey marshalled to empty bytes for tx %s", tx.ID)
		}
	} else {
		log.Printf("WARN: [convertToThrylosTransaction] Input tx.SenderPublicKey is nil for tx %s.", tx.ID)
		// thrylosTx.SenderPublicKey will remain its zero value (likely nil or empty slice)
	}
	// --- End Handle SenderPublicKey ---

	// --- Convert Inputs --- (Ensure this logic is correct from previous steps)
	if len(tx.Inputs) > 0 {
		thrylosTx.Inputs = make([]*thrylos.UTXO, len(tx.Inputs))
		log.Printf("DEBUG: [convertToThrylosTransaction] Converting %d inputs for tx %s", len(tx.Inputs), tx.ID)
		for i, inputUtxo := range tx.Inputs {
			thrylosTx.Inputs[i] = convertTypesUTXOToProtoUTXO(inputUtxo)
		}
	} else { /* Assign empty slice */
		thrylosTx.Inputs = []*thrylos.UTXO{}
	}

	// --- Convert Outputs --- (Ensure this logic is correct from previous steps)
	if len(tx.Outputs) > 0 {
		thrylosTx.Outputs = make([]*thrylos.UTXO, len(tx.Outputs))
		log.Printf("DEBUG: [convertToThrylosTransaction] Converting %d outputs for tx %s", len(tx.Outputs), tx.ID)
		for i, outputUtxo := range tx.Outputs {
			thrylosTx.Outputs[i] = convertTypesUTXOToProtoUTXO(outputUtxo)
		}
	} else { /* Assign empty slice */
		thrylosTx.Outputs = []*thrylos.UTXO{}
	}

	// TODO: Assign other fields like Signature safely (with nil checks) if needed

	log.Printf("DEBUG: [convertToThrylosTransaction] Returning thrylosTx. Sender: %q, Inputs: %d, Outputs: %d, PK Len: %d", thrylosTx.Sender, len(thrylosTx.Inputs), len(thrylosTx.Outputs), len(thrylosTx.SenderPublicKey))
	return thrylosTx
}

// Ensure convertTypesUTXOToProtoUTXO exists and is correct
func convertTypesUTXOToProtoUTXO(typeUtxo types.UTXO) *thrylos.UTXO {
	// Add nil checks or validation if necessary
	if typeUtxo.OwnerAddress == "" {
		log.Printf("WARN: [convertTypesUTXOToProtoUTXO] converting UTXO with empty OwnerAddress (TxID: %s, Index: %d)", typeUtxo.TransactionID, typeUtxo.Index)
		// Depending on rules, maybe return nil or allow empty address?
	}
	return &thrylos.UTXO{
		TransactionId: typeUtxo.TransactionID,
		Index:         int32(typeUtxo.Index),  // Convert int to int32
		OwnerAddress:  typeUtxo.OwnerAddress,  // Assuming string
		Amount:        int64(typeUtxo.Amount), // Assuming amount.Amount is int64 or convertible
		IsSpent:       typeUtxo.IsSpent,
		// Ensure all relevant fields from types.UTXO are mapped
	}
}

func (h *Handler) handleEstimateGas(params []interface{}) (interface{}, error) {
	// Log the incoming request
	log.Printf("estimateGas JSON-RPC method called")

	// Check if params exist
	if len(params) < 1 {
		return nil, fmt.Errorf("dataSize parameter required")
	}

	// Extract dataSize from params
	dataSizeFloat, ok := params[0].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid dataSize parameter: must be a number")
	}

	// Convert float64 to int
	dataSize := int(dataSizeFloat)

	// Create response channel
	responseCh := make(chan types.Response)

	// Send message to estimate gas
	h.messageBus.Publish(types.Message{
		Type: types.EstimateGas, // Now defined
		Data: map[string]interface{}{
			"dataSize": dataSize,
			"txType":   0, // Default transaction type
		},
		ResponseCh: responseCh,
	})

	// Wait for response
	response := <-responseCh

	if response.Error != nil {
		return nil, fmt.Errorf("error estimating gas: %v", response.Error)
	}

	// Convert response data to gas fee
	gas, ok := response.Data.(int)
	if !ok {
		return nil, fmt.Errorf("invalid gas fee data type")
	}

	// Log the estimation
	log.Printf("Gas fee estimate calculated: %d for data size: %d", gas, dataSize)

	// Return structured response
	return struct {
		GasFee     int    `json:"gasFee"`
		GasFeeUnit string `json:"gasFeeUnit"`
	}{
		GasFee:     gas,
		GasFeeUnit: "nanoTHRYLOS",
	}, nil
}

// Main handler for staking operations
func (h *Handler) handleStaking(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("parameters required")
	}

	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	// Extract operation type
	operation, ok := reqData["operation"].(string)
	if !ok {
		return nil, fmt.Errorf("operation field required")
	}

	switch operation {
	case "stake":
		return h.handleStakeOperation(reqData)
	case "validate":
		return h.handleValidateStakeOperation(reqData)
	default:
		return nil, fmt.Errorf("unknown operation: %s", operation)
	}
}

func (h *Handler) handleStakeOperation(reqData map[string]interface{}) (interface{}, error) {
	// Extract required fields
	userAddress, ok := reqData["userAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("userAddress required")
	}

	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	validatorAddress, ok := reqData["validatorAddress"].(string)
	if !ok {
		return nil, fmt.Errorf("validatorAddress required")
	}

	// Create response channels for various operations
	minStakeCh := make(chan types.Response)
	validatorExistsCh := make(chan types.Response)
	balanceCh := make(chan types.Response)
	createStakeCh := make(chan types.Response)

	// Get minimum stake amount
	h.messageBus.Publish(types.Message{
		Type:       types.GetStakingStats,
		Data:       "minStakeAmount",
		ResponseCh: minStakeCh,
	})

	// Check if validator exists and is active
	h.messageBus.Publish(types.Message{
		Type: types.ValidateValidator,
		Data: map[string]interface{}{
			"address": validatorAddress,
		},
		ResponseCh: validatorExistsCh,
	})

	// Get user balance
	h.messageBus.Publish(types.Message{
		Type:       types.GetBalance,
		Data:       userAddress,
		ResponseCh: balanceCh,
	})

	// Wait for responses
	minStakeResp := <-minStakeCh
	validatorResp := <-validatorExistsCh
	balanceResp := <-balanceCh

	// Process responses
	if minStakeResp.Error != nil {
		return nil, fmt.Errorf("failed to get minimum stake: %v", minStakeResp.Error)
	}
	minStake, ok := minStakeResp.Data.(int64)
	if !ok {
		return nil, fmt.Errorf("invalid minimum stake data type")
	}

	// Validate minimum stake
	if amount < minStake {
		return nil, fmt.Errorf("stake amount must be at least %d THRYLOS", minStake/1e7)
	}

	// Validate validator exists and is active
	if validatorResp.Error != nil || validatorResp.Data == nil {
		return nil, fmt.Errorf("invalid validator address")
	}
	validatorExists, ok := validatorResp.Data.(bool)
	if !ok || !validatorExists {
		return nil, fmt.Errorf("validator does not exist or is not active")
	}

	// Check user's balance
	if balanceResp.Error != nil {
		return nil, fmt.Errorf("failed to get balance: %v", balanceResp.Error)
	}
	balance, ok := balanceResp.Data.(int64)
	if !ok {
		return nil, fmt.Errorf("invalid balance data type")
	}

	if balance < amount+1000 { // Including gas fee
		return nil, fmt.Errorf("insufficient balance for staking")
	}

	// Create stake record via message bus
	h.messageBus.Publish(types.Message{
		Type: types.CreateStake,
		Data: map[string]interface{}{
			"userAddress": userAddress,
			"amount":      amount,
			"validator":   validatorAddress,
		},
		ResponseCh: createStakeCh,
	})

	// Wait for stake creation response
	createStakeResp := <-createStakeCh
	if createStakeResp.Error != nil {
		return nil, fmt.Errorf("failed to create stake: %v", createStakeResp.Error)
	}

	// Get stake record from response
	stakeRecord, ok := createStakeResp.Data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid stake record data type")
	}

	// Create staking transaction ID
	stakingTxId := fmt.Sprintf("stake-%s-%d", userAddress, time.Now().UnixNano())

	// Get inflation rate for response
	effectiveRateCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetStakingStats,
		Data:       "effectiveRate",
		ResponseCh: effectiveRateCh,
	})
	effectiveRateResp := <-effectiveRateCh
	effectiveRate := "4.8%"
	if effectiveRateResp.Error == nil {
		if rate, ok := effectiveRateResp.Data.(float64); ok {
			effectiveRate = fmt.Sprintf("%.2f%%", rate)
		}
	}

	// Get staking pool info for last reward time
	poolInfoCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetPoolStats,
		Data:       nil,
		ResponseCh: poolInfoCh,
	})
	poolInfoResp := <-poolInfoCh

	// Extract last reward time and calculate next reward time
	lastRewardTime := time.Now().Unix()
	if poolInfoResp.Error == nil {
		if poolInfo, ok := poolInfoResp.Data.(map[string]interface{}); ok {
			if lrt, ok := poolInfo["lastRewardTime"].(int64); ok {
				lastRewardTime = lrt
			}
		}
	}
	nextRewardTime := lastRewardTime + (24 * 3600) // 24 hours in seconds

	// Get active validators count
	validatorsCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetValidators,
		Data:       nil,
		ResponseCh: validatorsCh,
	})
	validatorsResp := <-validatorsCh
	activeValidatorsCount := 1
	if validatorsResp.Error == nil {
		if validators, ok := validatorsResp.Data.([]interface{}); ok {
			activeValidatorsCount = len(validators)
		}
	}

	// Format response
	return map[string]interface{}{
		"message": "Stake created successfully",
		"stake": map[string]interface{}{
			"amount":         float64(amount) / 1e7,
			"amountRaw":      amount,
			"startTime":      stakeRecord["startTime"],
			"isActive":       stakeRecord["isActive"],
			"validatorRole":  stakeRecord["validatorRole"],
			"lastRewardTime": lastRewardTime,
		},
		"transactionId": stakingTxId,
		"stakingInfo": map[string]interface{}{
			"yearlyReward":         "4.8M",
			"effectiveRate":        effectiveRate,
			"minStakeAmount":       float64(minStake) / 1e7,
			"nextRewardTime":       nextRewardTime,
			"rewardInterval":       "24h",
			"activeValidators":     activeValidatorsCount,
			"estimatedDailyReward": 4800000.0 / 365.0 / float64(activeValidatorsCount) / 1e7,
		},
	}, nil
}

func (h *Handler) handleValidateStakeOperation(reqData map[string]interface{}) (interface{}, error) {
	amountFloat, ok := reqData["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("amount required")
	}
	amount := int64(amountFloat)

	// Get minimum stake amount
	minStakeCh := make(chan types.Response)
	h.messageBus.Publish(types.Message{
		Type:       types.GetStakingStats,
		Data:       "minStakeAmount",
		ResponseCh: minStakeCh,
	})

	// Wait for response
	minStakeResp := <-minStakeCh
	if minStakeResp.Error != nil {
		return nil, fmt.Errorf("failed to get minimum stake: %v", minStakeResp.Error)
	}

	minStake, ok := minStakeResp.Data.(int64)
	if !ok {
		return nil, fmt.Errorf("invalid minimum stake data type")
	}

	if amount < minStake {
		return nil, fmt.Errorf("minimum stake is %d THR", minStake/1e7)
	}

	return map[string]interface{}{
		"valid": true,
	}, nil
}

func (h *Handler) handleGetStakingInfo(params []interface{}) (interface{}, error) {
	if len(params) < 1 {
		return nil, fmt.Errorf("address parameter required")
	}

	// Extract address
	reqData, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format")
	}

	userAddress, ok := reqData["address"].(string)
	if !ok {
		return nil, fmt.Errorf("address parameter required")
	}

	// Create response channels
	stakingInfoCh := make(chan types.Response)
	poolInfoCh := make(chan types.Response)
	validatorCh := make(chan types.Response)

	// Send requests in parallel
	h.messageBus.Publish(types.Message{
		Type:       types.GetStakingStats,
		Data:       userAddress,
		ResponseCh: stakingInfoCh,
	})

	h.messageBus.Publish(types.Message{
		Type:       types.GetPoolStats,
		Data:       nil,
		ResponseCh: poolInfoCh,
	})

	h.messageBus.Publish(types.Message{
		Type: types.IsValidator,
		Data: map[string]interface{}{
			"address": userAddress,
		},
		ResponseCh: validatorCh,
	})

	// Collect responses
	stakingInfoResp := <-stakingInfoCh
	poolInfoResp := <-poolInfoCh
	validatorResp := <-validatorCh

	// Initialize with default values
	totalStaked := int64(0)
	totalRewards := int64(0)
	isValidator := false
	activeStakes := make([]*types.Stake, 0)
	currentTime := time.Now().Unix()
	nextRewardTime := currentTime + (24 * 3600)
	stakingPool := map[string]interface{}{
		"minStakeAmount": int64(10000000000), // 1000 THR in nano
		"totalStaked":    int64(0),
		"lastRewardTime": currentTime - (12 * 3600), // 12 hours ago
	}

	// Process staking info response
	if stakingInfoResp.Error == nil {
		if info, ok := stakingInfoResp.Data.(map[string]interface{}); ok {
			if ts, ok := info["totalStaked"].(int64); ok {
				totalStaked = ts
			} else if tsMap, ok := info["totalStaked"].(map[string]interface{}); ok {
				if nano, ok := tsMap["nano"].(int64); ok {
					totalStaked = nano
				}
			}

			if tr, ok := info["totalRewards"].(int64); ok {
				totalRewards = tr
			} else if trMap, ok := info["totalRewards"].(map[string]interface{}); ok {
				if nano, ok := trMap["nano"].(int64); ok {
					totalRewards = nano
				}
			}

			if stakes, ok := info["activeStakes"].([]types.Stake); ok {
				for _, stake := range stakes {
					activeStakes = append(activeStakes, &stake)
				}
			}
		}
	}

	// Process pool info response
	if poolInfoResp.Error == nil {
		if pool, ok := poolInfoResp.Data.(map[string]interface{}); ok {
			if minStake, ok := pool["minStakeAmount"].(int64); ok {
				stakingPool["minStakeAmount"] = minStake
			}

			if totalPoolStake, ok := pool["totalStaked"].(int64); ok {
				stakingPool["totalStaked"] = totalPoolStake
			}

			if lastRewardTime, ok := pool["lastRewardTime"].(int64); ok {
				stakingPool["lastRewardTime"] = lastRewardTime
				nextRewardTime = lastRewardTime + (24 * 3600)
			}
		}
	}

	// Process validator response
	if validatorResp.Error == nil {
		if v, ok := validatorResp.Data.(bool); ok {
			isValidator = v
		}
	}

	// Calculate time until next reward
	lastRewardTime, _ := stakingPool["lastRewardTime"].(int64)
	timeUntilNextReward := (lastRewardTime + 24*3600) - currentTime
	if timeUntilNextReward < 0 {
		timeUntilNextReward = 0
	}

	// Return structured response
	return map[string]interface{}{
		"address":     userAddress,
		"isValidator": isValidator,
		"staking": map[string]interface{}{
			"totalStaked": map[string]interface{}{
				"thrylos": float64(totalStaked) / 1e7,
				"nano":    totalStaked,
			},
			"totalRewards": map[string]interface{}{
				"thrylos": float64(totalRewards) / 1e7,
				"nano":    totalRewards,
			},
			"activeStakesCount": len(activeStakes),
			"activeStakes":      activeStakes,
			"nextRewardTime":    nextRewardTime,
		},
		"stakingPool": map[string]interface{}{
			"minStakeAmount": map[string]interface{}{
				"thrylos": float64(stakingPool["minStakeAmount"].(int64)) / 1e7,
				"nano":    stakingPool["minStakeAmount"].(int64),
			},
			"totalStaked": map[string]interface{}{
				"thrylos": float64(stakingPool["totalStaked"].(int64)) / 1e7,
				"nano":    stakingPool["totalStaked"].(int64),
			},
			"rewardSchedule": map[string]interface{}{
				"interval":             "24h",
				"lastRewardTime":       lastRewardTime,
				"nextRewardTime":       nextRewardTime,
				"timeUntilNextReward":  timeUntilNextReward,
				"estimatedDailyReward": float64(4800000) / 365.0 / 10.0 / 1e7, // Assuming 10 validators
			},
			"rewardInfo": map[string]interface{}{
				"yearlyReward":       "4.8M",
				"effectiveRate":      "4.8%",
				"rewardDistribution": "Daily",
			},
		},
	}, nil
}

/// Get Balance test curl
// curl -X POST http://localhost:50051/ \
//   -H "Content-Type: application/json" \
//   -d '{"jsonrpc":"2.0","method":"getBalance","params":["tl1839b4955945b1607"],"id":1}' \
//   -v
