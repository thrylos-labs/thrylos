package core

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
)

// Gas fee constants
const (
	BaseGasFee = 1000  // Base fee in microTHRYLOS (0.001 THRYLOS)
	MaxGasFee  = 10000 // Maximum gas fee in microTHRYLOS (0.01 THRYLOS)
)

func (n *Node) handleProcessedTransaction(tx *thrylos.Transaction) {
	addresses := make(map[string]bool)
	addresses[tx.Sender] = true
	for _, output := range tx.Outputs {
		addresses[output.OwnerAddress] = true
	}

	for address := range addresses {
		if err := n.SendBalanceUpdate(address); err != nil {
			log.Printf("Failed to send balance update for %s: %v", address, err)
		}
	}
}

// HasTransaction checks whether a transaction with the specified ID exists in the node's pool of pending transactions.
func (node *Node) HasTransaction(txID string) bool {
	for _, tx := range node.PendingTransactions {
		if tx.GetId() == txID {
			return true
		}
	}
	return false
}

// Transaction verification and processing
func (node *Node) VerifyAndProcessTransaction(tx *thrylos.Transaction) error {
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction has no inputs")
	}

	senderAddress := tx.Sender
	if senderAddress == "" {
		log.Printf("Transaction with empty sender address: %+v", tx)
		return fmt.Errorf("sender address is empty")
	}

	if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(senderAddress) {
		log.Printf("Invalid sender address format: %s", senderAddress)
		return fmt.Errorf("invalid sender address format: %s", senderAddress)
	}

	log.Printf("VerifyAndProcessTransaction: Verifying transaction for sender address: %s", senderAddress)

	senderEd25519PublicKey, err := node.Blockchain.RetrievePublicKey(senderAddress)
	if err != nil {
		log.Printf("VerifyAndProcessTransaction: Failed to retrieve or validate Ed25519 public key for address %s: %v", senderAddress, err)
		return fmt.Errorf("failed to retrieve or validate Ed25519 public key: %v", err)
	}

	if err := shared.VerifyTransactionSignature(tx, senderEd25519PublicKey); err != nil {
		return fmt.Errorf("transaction signature verification failed: %v", err)
	}

	return nil
}

// Transaction input collection
func (node *Node) CollectInputsForTransaction(amount int64, senderAddress string) (inputs []shared.UTXO, change int64, err error) {
	var collectedAmount int64
	var collectedInputs []shared.UTXO

	utxos, err := node.Blockchain.GetUTXOsForAddress(senderAddress)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range utxos {
		if collectedAmount >= amount {
			break
		}
		collectedAmount += utxo.Amount
		collectedInputs = append(collectedInputs, utxo)
	}

	if collectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds available")
	}

	change = collectedAmount - amount
	return collectedInputs, change, nil
}

// Gas calculation
func CalculateGas(dataSize int, balance int64) int {
	gasFee := BaseGasFee
	additionalFee := (dataSize / 1000) * 100
	gasFee += additionalFee

	if gasFee > MaxGasFee {
		gasFee = MaxGasFee
	}

	return gasFee
}

// Transaction validation
func (n *Node) validateTransactionAddresses(tx *shared.Transaction) error {
	_, err := n.Database.RetrievePublicKeyFromAddress(tx.Sender)
	if err != nil {
		log.Printf("Invalid sender address %s: %v", tx.Sender, err)
		return fmt.Errorf("invalid sender address: %v", err)
	}

	for _, output := range tx.Outputs {
		_, err := n.Database.RetrievePublicKeyFromAddress(output.OwnerAddress)
		if err != nil {
			log.Printf("Invalid output address %s: %v", output.OwnerAddress, err)
			return fmt.Errorf("invalid output address %s: %v", output.OwnerAddress, err)
		}
	}

	return nil
}

// Transaction conversion utilities
func ConvertThrylosToProtoTransaction(thrylosTx *thrylos.Transaction) *thrylos.Transaction {
	return thrylosTx
}

func ThrylosToShared(tx *thrylos.Transaction) *shared.Transaction {
	if tx == nil {
		return nil
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(tx.GetSignature())

	return &shared.Transaction{
		ID:            tx.GetId(),
		Timestamp:     tx.GetTimestamp(),
		Inputs:        ConvertProtoInputs(tx.GetInputs()),
		Outputs:       ConvertProtoOutputs(tx.GetOutputs()),
		Signature:     signatureBase64,
		PreviousTxIds: tx.GetPreviousTxIds(),
	}
}

func ConvertProtoInputs(inputs []*thrylos.UTXO) []shared.UTXO {
	sharedInputs := make([]shared.UTXO, len(inputs))
	for i, input := range inputs {
		if input != nil {
			sharedInputs[i] = shared.UTXO{
				TransactionID: input.GetTransactionId(),
				Index:         int(input.GetIndex()),
				OwnerAddress:  input.GetOwnerAddress(),
				Amount:        int64(input.GetAmount()),
			}
		}
	}
	return sharedInputs
}

func ConvertProtoOutputs(outputs []*thrylos.UTXO) []shared.UTXO {
	sharedOutputs := make([]shared.UTXO, len(outputs))
	for i, output := range outputs {
		if output != nil {
			sharedOutputs[i] = shared.UTXO{
				TransactionID: output.GetTransactionId(),
				Index:         int(output.GetIndex()),
				OwnerAddress:  output.GetOwnerAddress(),
				Amount:        int64(output.GetAmount()),
			}
		}
	}
	return sharedOutputs
}

// Pending transaction management
func (node *Node) AddPendingTransaction(tx *thrylos.Transaction) error {
	node.Blockchain.Mu.Lock()
	defer node.Blockchain.Mu.Unlock()

	if tx == nil {
		return fmt.Errorf("cannot add nil transaction")
	}

	log.Printf("=== Starting AddPendingTransaction ===")
	log.Printf("Transaction ID: %s", tx.Id)

	for _, pendingTx := range node.Blockchain.PendingTransactions {
		if pendingTx.Id == tx.Id {
			log.Printf("Warning: Transaction %s already exists in pending pool, skipping", tx.Id)
			return nil
		}
	}

	node.Blockchain.PendingTransactions = append(node.Blockchain.PendingTransactions, tx)
	pendingCount := len(node.Blockchain.PendingTransactions)

	if err := node.Blockchain.UpdateTransactionStatus(tx.Id, "pending", nil); err != nil {
		log.Printf("Warning: Error updating transaction status: %v", err)
	}

	if pendingCount == 1 {
		go node.TriggerBlockCreation()
	}

	log.Printf("Transaction %s successfully added to pending pool. Total pending: %d",
		tx.Id, pendingCount)

	balanceCache.Delete(tx.Sender)
	for _, output := range tx.Outputs {
		balanceCache.Delete(output.OwnerAddress)
	}

	return nil
}

func (node *Node) GetPendingTransactions() []*thrylos.Transaction {
	return node.PendingTransactions
}

func calculateTotalAmount(outputs []*thrylos.UTXO) int64 {
	var total int64
	for _, utxo := range outputs {
		total += int64(utxo.Amount)
	}
	return total
}

func (n *Node) updateBalances(tx *thrylos.Transaction) error {
	senderBalance, err := n.Blockchain.GetBalance(tx.Sender)
	if err != nil {
		return fmt.Errorf("failed to get sender balance: %v", err)
	}
	log.Printf("Updated sender (%s) balance: %s", tx.Sender, senderBalance.String())

	for _, output := range tx.Outputs {
		recipientBalance, err := n.Blockchain.GetBalance(output.OwnerAddress)
		if err != nil {
			return fmt.Errorf("failed to get recipient balance: %v", err)
		}
		log.Printf("Updated recipient (%s) balance: %s", output.OwnerAddress, recipientBalance.String())
	}

	return nil
}

// JSON conversion
func ConvertJSONToProto(jsonTx thrylos.TransactionJSON) *thrylos.Transaction {
	tx := &thrylos.Transaction{
		Id:        jsonTx.ID,
		Timestamp: jsonTx.Timestamp,
		Signature: []byte(jsonTx.Signature),
	}

	for _, input := range jsonTx.Inputs {
		tx.Inputs = append(tx.Inputs, &thrylos.UTXO{
			TransactionId: input.TransactionID,
			Index:         input.Index,
			OwnerAddress:  input.OwnerAddress,
			Amount:        input.Amount,
		})
	}

	for _, output := range jsonTx.Outputs {
		tx.Outputs = append(tx.Outputs, &thrylos.UTXO{
			TransactionId: output.TransactionID,
			Index:         output.Index,
			OwnerAddress:  output.OwnerAddress,
			Amount:        output.Amount,
		})
	}

	return tx
}
