package processor

// import (
// 	"encoding/base64"
// 	"encoding/hex"
// 	"fmt"
// 	"log"
// 	"regexp"
// 	"strings"
// 	"sync"

// 	thrylos "github.com/thrylos-labs/thrylos"
// 	"github.com/thrylos-labs/thrylos/core/balance"
// 	"github.com/thrylos-labs/thrylos/shared"
// )

// // Gas fee constants
// const (
// 	BaseGasFee = 1000  // Base fee in microTHRYLOS (0.001 THRYLOS)
// 	MaxGasFee  = 10000 // Maximum gas fee in microTHRYLOS (0.01 THRYLOS)
// )

// // Staking transaction types
// const (
// 	TxTypeStake   = "stake"
// 	TxTypeUnstake = "unstake"
// )

// type TransactionStatus struct {
// 	ProcessedByModern bool
// 	ConfirmedByDAG    bool
// 	sync.Mutex
// }

// func (n *Node) handleProcessedTransaction(tx *thrylos.Transaction) {
// 	txID := tx.GetId()
// 	log.Printf("Starting final processing for transaction %s", txID)

// 	// Get transaction status
// 	statusIface, exists := n.txStatusMap.Load(txID)
// 	if !exists {
// 		log.Printf("Warning: Transaction status not found for %s", txID)
// 		return
// 	}

// 	status := statusIface.(*TransactionStatus)
// 	status.Lock()
// 	defer status.Unlock()

// 	// Only process if both conditions are met
// 	if !status.ProcessedByModern || !status.ConfirmedByDAG {
// 		return
// 	}

// 	// Collect affected addresses
// 	addresses := make(map[string]bool)
// 	addresses[tx.Sender] = true
// 	for _, output := range tx.Outputs {
// 		addresses[output.OwnerAddress] = true
// 	}

// 	// Queue balance updates with retries
// 	for address := range addresses {
// 		// Use the existing queue channel
// 		n.balanceUpdateQueue.queue <- balance.BalanceUpdateRequest{
// 			Address: address,
// 			Retries: 5, // Use same retry count as UpdateBalanceAsync
// 		}
// 	}

// 	// Clear transaction status after queuing updates
// 	n.txStatusMap.Delete(txID)
// 	log.Printf("Completed processing transaction %s", txID)
// }

// // HasTransaction checks whether a transaction with the specified ID exists in the node's pool of pending transactions.
// func (node *Node) HasTransaction(txID string) bool {
// 	for _, tx := range node.PendingTransactions {
// 		if tx.GetId() == txID {
// 			return true
// 		}
// 	}
// 	return false
// }

// // Transaction verification and processing
// func (node *Node) VerifyAndProcessTransaction(tx *thrylos.Transaction) error {
// 	// Check if this is a staking transaction
// 	if isStakingTransaction(tx) {
// 		return node.processStakingTransaction(tx)
// 	}

// 	if len(tx.Inputs) == 0 {
// 		return fmt.Errorf("transaction has no inputs")
// 	}

// 	senderAddress := tx.Sender
// 	if senderAddress == "" {
// 		log.Printf("Transaction with empty sender address: %+v", tx)
// 		return fmt.Errorf("sender address is empty")
// 	}

// 	if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(senderAddress) {
// 		log.Printf("Invalid sender address format: %s", senderAddress)
// 		return fmt.Errorf("invalid sender address format: %s", senderAddress)
// 	}

// 	log.Printf("VerifyAndProcessTransaction: Verifying transaction for sender address: %s", senderAddress)

// 	senderMLDSAPublicKey, err := node.Blockchain.RetrievePublicKey(senderAddress)
// 	if err != nil {
// 		log.Printf("VerifyAndProcessTransaction: Failed to retrieve or validate MLDSA public key for address %s: %v", senderAddress, err)
// 		return fmt.Errorf("failed to retrieve or validate MLDSA public key: %v", err)
// 	}

// 	if err := shared.VerifyTransactionSignature(tx, senderMLDSAPublicKey); err != nil {
// 		return fmt.Errorf("transaction signature verification failed: %v", err)
// 	}

// 	return nil
// }

// // In transaction processor code
// func (node *Node) processStakingTransaction(tx *thrylos.Transaction) error {
// 	txType := getStakingTransactionType(tx)
// 	log.Printf("Processing %s transaction: %s", txType, tx.Id)

// 	switch txType {
// 	case TxTypeStake:
// 		if tx.Outputs[0].OwnerAddress != "staking_pool" {
// 			return fmt.Errorf("invalid staking transaction: incorrect recipient")
// 		}

// 		// Only update the staking service state
// 		// Database transaction will be handled by the normal transaction flow
// 		stake := &Stake{
// 			UserAddress:         tx.Sender,
// 			Amount:              tx.Outputs[0].Amount,
// 			StartTime:           tx.Timestamp,
// 			LastStakeUpdateTime: tx.Timestamp,
// 			IsActive:            true,
// 			ValidatorRole:       true,
// 		}

// 		// Update staking service state
// 		node.stakingService.stakes[tx.Sender] = stake
// 		node.stakingService.pool.TotalStaked += tx.Outputs[0].Amount

// 	case TxTypeUnstake:
// 		if tx.Sender != "staking_pool" {
// 			return fmt.Errorf("invalid unstaking transaction: incorrect sender")
// 		}

// 		stakeholder := tx.Outputs[0].OwnerAddress
// 		unstakeAmount := tx.Outputs[0].Amount

// 		// Verify stake exists in staking service
// 		if stake := node.stakingService.stakes[stakeholder]; stake != nil {
// 			if stake.Amount < unstakeAmount {
// 				return fmt.Errorf("insufficient stake for unstaking")
// 			}

// 			// Update stake record
// 			stake.Amount -= unstakeAmount
// 			stake.LastStakeUpdateTime = tx.Timestamp
// 			if stake.Amount == 0 {
// 				stake.IsActive = false
// 			}
// 			node.stakingService.pool.TotalStaked -= unstakeAmount
// 		} else {
// 			return fmt.Errorf("no active stake found for %s", stakeholder)
// 		}

// 	default:
// 		return fmt.Errorf("unknown staking transaction type: %s", txType)
// 	}

// 	log.Printf("Successfully processed %s transaction: %s", txType, tx.Id)
// 	return nil
// }

// func isStakingTransaction(tx *thrylos.Transaction) bool {
// 	return strings.HasPrefix(tx.Id, "stake-") || strings.HasPrefix(tx.Id, "unstake-")
// }

// func getStakingTransactionType(tx *thrylos.Transaction) string {
// 	if strings.HasPrefix(tx.Id, "stake-") {
// 		return TxTypeStake
// 	}
// 	if strings.HasPrefix(tx.Id, "unstake-") {
// 		return TxTypeUnstake
// 	}
// 	return "unknown"
// }

// // Transaction input collection
// func (node *Node) CollectInputsForTransaction(amount int64, senderAddress string) (inputs []shared.UTXO, change int64, err error) {
// 	var collectedAmount int64
// 	var collectedInputs []shared.UTXO

// 	utxos, err := node.Blockchain.GetUTXOsForAddress(senderAddress)
// 	if err != nil {
// 		return nil, 0, err
// 	}

// 	for _, utxo := range utxos {
// 		if collectedAmount >= amount {
// 			break
// 		}
// 		collectedAmount += utxo.Amount
// 		collectedInputs = append(collectedInputs, utxo)
// 	}

// 	if collectedAmount < amount {
// 		return nil, 0, fmt.Errorf("not enough funds available")
// 	}

// 	change = collectedAmount - amount
// 	return collectedInputs, change, nil
// }

// // Gas calculation
// func CalculateGas(dataSize int, balance int64) int {
// 	gasFee := BaseGasFee
// 	additionalFee := (dataSize / 1000) * 100
// 	gasFee += additionalFee

// 	if gasFee > MaxGasFee {
// 		gasFee = MaxGasFee
// 	}

// 	return gasFee
// }

// // Transaction validation
// func (n *Node) validateTransactionAddresses(tx *shared.Transaction) error {
// 	_, err := n.Database.RetrievePublicKeyFromAddress(tx.Sender)
// 	if err != nil {
// 		log.Printf("Invalid sender address %s: %v", tx.Sender, err)
// 		return fmt.Errorf("invalid sender address: %v", err)
// 	}

// 	for _, output := range tx.Outputs {
// 		_, err := n.Database.RetrievePublicKeyFromAddress(output.OwnerAddress)
// 		if err != nil {
// 			log.Printf("Invalid output address %s: %v", output.OwnerAddress, err)
// 			return fmt.Errorf("invalid output address %s: %v", output.OwnerAddress, err)
// 		}
// 	}

// 	return nil
// }

// // Transaction conversion utilities
// func ConvertThrylosToProtoTransaction(thrylosTx *thrylos.Transaction) *thrylos.Transaction {
// 	return thrylosTx
// }

// func ThrylosToShared(tx *thrylos.Transaction) *shared.Transaction {
// 	if tx == nil {
// 		return nil
// 	}

// 	// Convert signature to base64 if it exists
// 	var signatureBase64 string
// 	if tx.GetSignature() != nil {
// 		signatureBase64 = base64.StdEncoding.EncodeToString(tx.GetSignature())
// 	}

// 	// Convert BlockHash to string if it exists
// 	var blockHashStr string
// 	if tx.GetBlockHash() != nil {
// 		blockHashStr = hex.EncodeToString(tx.GetBlockHash())
// 	}

// 	return &shared.Transaction{
// 		ID:               tx.GetId(),
// 		Timestamp:        tx.GetTimestamp(),
// 		Inputs:           ConvertProtoInputs(tx.GetInputs()),
// 		Outputs:          ConvertProtoOutputs(tx.GetOutputs()),
// 		EncryptedInputs:  tx.GetEncryptedInputs(),
// 		EncryptedOutputs: tx.GetEncryptedOutputs(),
// 		Signature:        signatureBase64,
// 		EncryptedAESKey:  tx.GetEncryptedAesKey(),
// 		PreviousTxIds:    tx.GetPreviousTxIds(),
// 		Sender:           tx.GetSender(),
// 		GasFee:           int(tx.GetGasfee()),
// 		SenderPublicKey:  tx.GetSenderPublicKey(),
// 		Status:           tx.GetStatus(),
// 		BlockHash:        blockHashStr,
// 		Salt:             tx.GetSalt(),
// 	}
// }

// func ConvertProtoInputs(inputs []*thrylos.UTXO) []shared.UTXO {
// 	sharedInputs := make([]shared.UTXO, len(inputs))
// 	for i, input := range inputs {
// 		if input != nil {
// 			sharedInputs[i] = shared.UTXO{
// 				TransactionID: input.GetTransactionId(),
// 				Index:         int(input.GetIndex()),
// 				OwnerAddress:  input.GetOwnerAddress(),
// 				Amount:        int64(input.GetAmount()),
// 			}
// 		}
// 	}
// 	return sharedInputs
// }

// func ConvertProtoOutputs(outputs []*thrylos.UTXO) []shared.UTXO {
// 	sharedOutputs := make([]shared.UTXO, len(outputs))
// 	for i, output := range outputs {
// 		if output != nil {
// 			sharedOutputs[i] = shared.UTXO{
// 				TransactionID: output.GetTransactionId(),
// 				Index:         int(output.GetIndex()),
// 				OwnerAddress:  output.GetOwnerAddress(),
// 				Amount:        int64(output.GetAmount()),
// 			}
// 		}
// 	}
// 	return sharedOutputs
// }

// const (
// 	// Transaction statuses
// 	TxStatusPending    = "pending"    // Transaction is in the pending pool
// 	TxStatusConfirmed  = "confirmed"  // Transaction is confirmed in a block
// 	TxStatusFailed     = "failed"     // Transaction failed to process
// 	TxStatusRejected   = "rejected"   // Transaction was rejected (invalid)
// 	TxStatusProcessing = "processing" // Transaction is being processed
// )

// // Then update the AddPendingTransaction function to use the constant:
// func (node *Node) AddPendingTransaction(tx *thrylos.Transaction) error {
// 	node.Blockchain.Mu.Lock()
// 	defer node.Blockchain.Mu.Unlock()

// 	if tx == nil {
// 		return fmt.Errorf("cannot add nil transaction")
// 	}

// 	log.Printf("=== Starting AddPendingTransaction ===")
// 	log.Printf("Transaction ID: %s", tx.Id)

// 	for _, pendingTx := range node.Blockchain.PendingTransactions {
// 		if pendingTx.Id == tx.Id {
// 			log.Printf("Warning: Transaction %s already exists in pending pool, skipping", tx.Id)
// 			return nil
// 		}
// 	}

// 	node.Blockchain.PendingTransactions = append(node.Blockchain.PendingTransactions, tx)
// 	pendingCount := len(node.Blockchain.PendingTransactions)

// 	// Use the constant instead of string literal
// 	if err := node.Blockchain.UpdateTransactionStatus(tx.Id, TxStatusPending, nil); err != nil {
// 		log.Printf("Warning: Error updating transaction status: %v", err)
// 	}

// 	if pendingCount == 1 {
// 		go node.TriggerBlockCreation()
// 	}

// 	log.Printf("Transaction %s successfully added to pending pool. Total pending: %d",
// 		tx.Id, pendingCount)

// 	balanceCache.Delete(tx.Sender)
// 	for _, output := range tx.Outputs {
// 		balanceCache.Delete(output.OwnerAddress)
// 	}

// 	return nil
// }

// func (node *Node) GetPendingTransactions() []*thrylos.Transaction {
// 	return node.PendingTransactions
// }

// func calculateTotalAmount(outputs []*thrylos.UTXO) int64 {
// 	var total int64
// 	for _, utxo := range outputs {
// 		total += int64(utxo.Amount)
// 	}
// 	return total
// }

// func (n *Node) updateBalances(tx *thrylos.Transaction) error {
// 	senderBalance, err := n.Blockchain.GetBalance(tx.Sender)
// 	if err != nil {
// 		return fmt.Errorf("failed to get sender balance: %v", err)
// 	}
// 	log.Printf("Updated sender (%s) balance: %d nanoTHRYLOS", tx.Sender, senderBalance)

// 	for _, output := range tx.Outputs {
// 		recipientBalance, err := n.Blockchain.GetBalance(output.OwnerAddress)
// 		if err != nil {
// 			return fmt.Errorf("failed to get recipient balance: %v", err)
// 		}
// 		log.Printf("Updated recipient (%s) balance: %d nanoTHRYLOS", output.OwnerAddress, recipientBalance)
// 	}

// 	return nil
// }

// // JSON conversion
// func ConvertJSONToProto(jsonTx thrylos.TransactionJSON) *thrylos.Transaction {
// 	tx := &thrylos.Transaction{
// 		Id:        jsonTx.ID,
// 		Timestamp: jsonTx.Timestamp,
// 		Signature: []byte(jsonTx.Signature),
// 	}

// 	for _, input := range jsonTx.Inputs {
// 		tx.Inputs = append(tx.Inputs, &thrylos.UTXO{
// 			TransactionId: input.TransactionID,
// 			Index:         input.Index,
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        input.Amount,
// 		})
// 	}

// 	for _, output := range jsonTx.Outputs {
// 		tx.Outputs = append(tx.Outputs, &thrylos.UTXO{
// 			TransactionId: output.TransactionID,
// 			Index:         output.Index,
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        output.Amount,
// 		})
// 	}

// 	return tx
// }
