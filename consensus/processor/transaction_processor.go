package processor

import (
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/balance"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/types"
)

type TransactionProcessorImpl struct {
	*types.TransactionPropagator
	txStatusMap        sync.Map
	balanceUpdateQueue *balance.BalanceUpdateQueue
	blockchain         *types.Blockchain       // Add reference to blockchain
	database           types.Store             // Add reference to database
	stakingService     *staking.StakingService // Add reference to staking service
}

// Staking transaction types
const (
	TxTypeStake   = "stake"
	TxTypeUnstake = "unstake"
)

type TransactionStatus struct {
	ProcessedByModern bool
	ConfirmedByDAG    bool
	sync.Mutex
}

// NewTransactionProcessorImpl creates a new instance of TransactionProcessorImpl
func NewTransactionProcessorImpl(
	propagator *types.TransactionPropagator,
	updateQueue *balance.BalanceUpdateQueue,
	blockchain *types.Blockchain,
	database types.Store,
	stakingService *staking.StakingService) *TransactionProcessorImpl {

	return &TransactionProcessorImpl{
		TransactionPropagator: propagator,
		balanceUpdateQueue:    updateQueue,
		blockchain:            blockchain,
		database:              database,
		stakingService:        stakingService,
	}
}

func (tp *TransactionProcessorImpl) handleProcessedTransaction(tx *thrylos.Transaction) {
	txID := tx.GetId()
	log.Printf("Starting final processing for transaction %s", txID)

	// Get transaction status
	statusIface, exists := tp.txStatusMap.Load(txID)
	if !exists {
		log.Printf("Warning: Transaction status not found for %s", txID)
		return
	}

	status := statusIface.(*TransactionStatus)
	status.Lock()
	defer status.Unlock()

	// Only process if both conditions are met
	if !status.ProcessedByModern || !status.ConfirmedByDAG {
		return
	}

	// Collect affected addresses
	addresses := make(map[string]bool)
	addresses[tx.Sender] = true
	for _, output := range tx.Outputs {
		addresses[output.OwnerAddress] = true
	}

	// Queue balance updates with retries
	// Queue balance updates with retries
	for address := range addresses {
		// Use the existing queue channel
		tp.balanceUpdateQueue.QueueUpdate(types.BalanceUpdateRequest{
			Address: address,
			Retries: 5, // Use same retry count as UpdateBalanceAsync
		}) // Remove the comma after the parenthesis
	}
	// Clear transaction status after queuing updates
	tp.txStatusMap.Delete(txID)
	log.Printf("Completed processing transaction %s", txID)
}

// HasTransaction checks whether a transaction with the specified ID exists in the node's pool of pending transactions.
func (tp *TransactionProcessorImpl) HasTransaction(txID string) bool {
	// Use the database to check if the transaction exists
	tx, err := tp.database.GetTransaction(txID)
	return err == nil && tx != nil
}

// Transaction verification and processing
// Transaction verification and processing
func (tp *TransactionProcessorImpl) VerifyAndProcessTransaction(tx *thrylos.Transaction) error {
	// Check if this is a staking transaction
	if isStakingTransaction(tx) {
		return tp.processStakingTransaction(tx)
	}

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

	// Convert to shared transaction type, which likely includes the public key
	sharedTx := ThrylosToShared(tx)

	// Since senderMLDSAPublicKey isn't used in the verification function,
	// we can skip retrieving it unless needed for other purposes

	// Call the verification function with just the transaction
	if err := shared.VerifyTransactionSignature(sharedTx); err != nil {
		return fmt.Errorf("transaction signature verification failed: %v", err)
	}

	return nil
}

// In transaction processor code
func (tp *TransactionProcessorImpl) processStakingTransaction(tx *thrylos.Transaction) error {
	txType := getStakingTransactionType(tx)
	log.Printf("Processing %s transaction: %s", txType, tx.Id)

	switch txType {
	case TxTypeStake:
		if tx.Outputs[0].OwnerAddress != "staking_pool" {
			return fmt.Errorf("invalid staking transaction: incorrect recipient")
		}

		// Use CreateStake method instead of directly manipulating fields
		amount := tx.Outputs[0].Amount
		_, err := tp.stakingService.CreateStake(tx.Sender, amount)
		if err != nil {
			return fmt.Errorf("failed to create stake: %v", err)
		}

	case TxTypeUnstake:
		if tx.Sender != "staking_pool" {
			return fmt.Errorf("invalid unstaking transaction: incorrect sender")
		}

		stakeholder := tx.Outputs[0].OwnerAddress
		unstakeAmount := tx.Outputs[0].Amount

		// Let's see if we can call a method to check if an address is a validator
		isDelegator := !tp.stakingService.IsValidator(stakeholder)

		err := tp.stakingService.UnstakeTokensInternal(stakeholder, isDelegator, unstakeAmount, tx.Timestamp)
		if err != nil {
			return fmt.Errorf("failed to unstake tokens: %v", err)
		}

	default:
		return fmt.Errorf("unknown staking transaction type: %s", txType)
	}

	log.Printf("Successfully processed %s transaction: %s", txType, tx.Id)
	return nil
}

func isStakingTransaction(tx *thrylos.Transaction) bool {
	return strings.HasPrefix(tx.Id, "stake-") || strings.HasPrefix(tx.Id, "unstake-")
}

func getStakingTransactionType(tx *thrylos.Transaction) string {
	if strings.HasPrefix(tx.Id, "stake-") {
		return TxTypeStake
	}
	if strings.HasPrefix(tx.Id, "unstake-") {
		return TxTypeUnstake
	}
	return "unknown"
}

// Transaction input collection
func (tp *TransactionProcessorImpl) CollectInputsForTransaction(amount int64, senderAddress string) (inputs []types.UTXO, change int64, err error) {
	var collectedAmount int64
	var collectedInputs []types.UTXO

	// Use the database instead of blockchain
	utxos, err := tp.database.GetUTXOsForAddress(senderAddress)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range utxos {
		if collectedAmount >= amount {
			break
		}

		utxoAmountInt64 := int64(utxo.Amount)
		collectedAmount += utxoAmountInt64
		collectedInputs = append(collectedInputs, utxo)
	}

	if collectedAmount < amount {
		return nil, 0, fmt.Errorf("not enough funds available")
	}

	change = collectedAmount - amount
	return collectedInputs, change, nil
}

// Transaction validation
func (tp *TransactionProcessorImpl) validateTransactionAddresses(tx *thrylos.Transaction) error {
	// Convert the sender string to an address.Address
	senderAddr, err := address.FromString(tx.Sender)
	if err != nil {
		log.Printf("Invalid sender address format %s: %v", tx.Sender, err)
		return fmt.Errorf("invalid sender address format: %v", err)
	}

	// Use GetPublicKey instead of RetrievePublicKeyFromAddress
	_, err = tp.database.GetPublicKey(*senderAddr)
	if err != nil {
		log.Printf("Invalid sender address %s: %v", tx.Sender, err)
		return fmt.Errorf("invalid sender address: %v", err)
	}

	for _, output := range tx.Outputs {
		// Convert each output owner address to address.Address
		outputAddr, err := address.FromString(output.OwnerAddress)
		if err != nil {
			log.Printf("Invalid output address format %s: %v", output.OwnerAddress, err)
			return fmt.Errorf("invalid output address format: %v", err)
		}

		// Use GetPublicKey instead of RetrievePublicKeyFromAddress
		_, err = tp.database.GetPublicKey(*outputAddr)
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

func ThrylosToShared(tx *thrylos.Transaction) *types.Transaction {
	if tx == nil {
		return nil
	}

	// Convert signature to crypto.Signature
	var signature crypto.Signature
	if tx.GetSignature() != nil {
		signature = crypto.NewSignature(tx.GetSignature())
	}

	// Convert sender public key to crypto.PublicKey
	var senderPublicKey crypto.PublicKey
	if tx.GetSenderPublicKey() != nil {
		// First convert to MLDSA public key
		mldsaPubKey := &mldsa44.PublicKey{}
		err := mldsaPubKey.UnmarshalBinary(tx.GetSenderPublicKey())
		if err != nil {
			log.Printf("Error unmarshaling sender public key: %v", err)
		} else {
			senderPublicKey = crypto.NewPublicKey(mldsaPubKey)
		}
	}

	// Convert sender address to address.Address
	var senderAddress *address.Address
	if tx.GetSender() != "" {
		var err error
		senderAddress, err = address.FromString(tx.GetSender())
		if err != nil {
			log.Printf("Error converting sender address: %v", err)
			// Create a null address as fallback
			senderAddress = address.NullAddress()
		}
	} else {
		senderAddress = address.NullAddress()
	}

	// Convert BlockHash to string if it exists
	var blockHashStr string
	if tx.GetBlockHash() != nil {
		blockHashStr = hex.EncodeToString(tx.GetBlockHash())
	}

	return &types.Transaction{
		ID:               tx.GetId(),
		Timestamp:        tx.GetTimestamp(),
		Inputs:           ConvertProtoInputs(tx.GetInputs()),
		Outputs:          ConvertProtoOutputs(tx.GetOutputs()),
		EncryptedInputs:  tx.GetEncryptedInputs(),
		EncryptedOutputs: tx.GetEncryptedOutputs(),
		EncryptedAESKey:  tx.GetEncryptedAesKey(),
		PreviousTxIds:    tx.GetPreviousTxIds(),
		SenderAddress:    *senderAddress, // Dereference pointer to get value
		SenderPublicKey:  senderPublicKey,
		Signature:        signature,
		GasFee:           int(tx.GetGasfee()),
		BlockHash:        blockHashStr,
		Salt:             tx.GetSalt(),
		Status:           tx.GetStatus(),
	}
}

func ConvertProtoInputs(inputs []*thrylos.UTXO) []types.UTXO {
	sharedInputs := make([]types.UTXO, len(inputs))
	for i, input := range inputs {
		if input != nil {
			// Convert int64 to amount.Amount directly since Amount is a type alias for int64
			amountValue := amount.Amount(input.GetAmount())

			sharedInputs[i] = types.UTXO{
				TransactionID: input.GetTransactionId(),
				Index:         int(input.GetIndex()),
				OwnerAddress:  input.GetOwnerAddress(),
				Amount:        amountValue,
			}
		}
	}
	return sharedInputs
}

func ConvertProtoOutputs(outputs []*thrylos.UTXO) []types.UTXO {
	sharedOutputs := make([]types.UTXO, len(outputs))
	for i, output := range outputs {
		if output != nil {
			// Convert int64 to amount.Amount directly
			amountValue := amount.Amount(output.GetAmount())

			sharedOutputs[i] = types.UTXO{
				TransactionID: output.GetTransactionId(),
				Index:         int(output.GetIndex()),
				OwnerAddress:  output.GetOwnerAddress(),
				Amount:        amountValue,
			}
		}
	}
	return sharedOutputs
}

const (
	// Transaction statuses
	TxStatusPending    = "pending"    // Transaction is in the pending pool
	TxStatusConfirmed  = "confirmed"  // Transaction is confirmed in a block
	TxStatusFailed     = "failed"     // Transaction failed to process
	TxStatusRejected   = "rejected"   // Transaction was rejected (invalid)
	TxStatusProcessing = "processing" // Transaction is being processed
)

func (tp *TransactionProcessorImpl) GetPendingTransactions() []*thrylos.Transaction {
	// Use tp.TransactionPropagator or database to get pending transactions
	return tp.blockchain.PendingTransactions
}

func calculateTotalAmount(outputs []*thrylos.UTXO) int64 {
	var total int64
	for _, utxo := range outputs {
		total += int64(utxo.Amount)
	}
	return total
}

func (tp *TransactionProcessorImpl) updateBalances(tx *thrylos.Transaction) error {
	// Convert sender address to proper format if needed
	senderAddr := tx.Sender

	// Use database instead of blockchain for balance lookup
	// The GetBalance method in Store takes an address and a UTXO map
	senderBalance, err := tp.database.GetBalance(senderAddr, nil)
	if err != nil {
		return fmt.Errorf("failed to get sender balance: %v", err)
	}
	log.Printf("Updated sender (%s) balance: %d nanoTHRYLOS", senderAddr, senderBalance)

	for _, output := range tx.Outputs {
		recipientAddr := output.OwnerAddress

		// Use database for recipient balance lookup
		recipientBalance, err := tp.database.GetBalance(recipientAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to get recipient balance: %v", err)
		}
		log.Printf("Updated recipient (%s) balance: %d nanoTHRYLOS", recipientAddr, recipientBalance)
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
