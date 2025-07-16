package chain

import (
	"fmt"
	"log"
	"time"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

// Conversion function will be needed when UTXO logic is added below
func convertTypesUTXOToProtoUTXO(typeUtxo types.UTXO) *thrylos.UTXO {
	protoUTXO := &thrylos.UTXO{
		TransactionId: typeUtxo.TransactionID,
		Index:         int32(typeUtxo.Index),
		OwnerAddress:  typeUtxo.OwnerAddress,
		Amount:        int64(typeUtxo.Amount),
		IsSpent:       typeUtxo.IsSpent,
	}

	if protoUTXO.TransactionId == "" || protoUTXO.OwnerAddress == "" {
		log.Printf("WARN: Conversion resulted in proto UTXO with missing TxID or OwnerAddress: %+v", protoUTXO)
	}
	return protoUTXO
}

func (bc *BlockchainImpl) HandleFundNewAddress(msg types.Message) {
	mapAddress := fmt.Sprintf("%p", &bc.ShardState.Stakeholders)
	log.Printf("DEBUG: HandleFundNewAddress using stakeholders map at address %s", mapAddress)
	log.Println("Handling FundNewAddress message")

	req, ok := msg.Data.(types.FundAddressRequest)
	if !ok {
		log.Println("Invalid fund request format")
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid fund request format")}
		return
	}

	// Get genesis address string
	var genesisAddr *address.Address
	var genesisAddrStr string
	var err error

	genesisPubKey := bc.ShardState.GenesisAccount.PublicKey()
	if genesisPubKey == nil {
		finalErr := fmt.Errorf("genesis account public key is nil")
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}

	genesisAddr, err = genesisPubKey.Address()
	if err != nil {
		finalErr := fmt.Errorf("failed to get address object from genesis public key: %v", err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	if genesisAddr == nil {
		finalErr := fmt.Errorf("genesis public key returned nil address object")
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}

	genesisAddrStr = genesisAddr.String()

	// --- Use Database Transaction for Atomicity ---
	var dbTxContext types.TransactionContext
	dbTxContext, err = bc.ShardState.Database.BeginTransaction()
	if err != nil {
		log.Printf("ERROR: HandleFundNewAddress failed to begin database transaction: %v", err)
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("failed to start DB transaction: %v", err)}
		return
	}
	var finalErr error
	defer func() {
		if finalErr != nil && dbTxContext != nil {
			log.Printf("WARN: Rolling back DB transaction in HandleFundNewAddress due to error: %v", finalErr)
			_ = bc.ShardState.Database.RollbackTransaction(dbTxContext)
		}
	}()

	// --- Lock In-Memory State ---
	bc.ShardState.Mu.Lock()
	defer bc.ShardState.Mu.Unlock()

	// --- Check Genesis Balance & Update In-Memory Stakeholders ---
	log.Printf("DEBUG: Began new DB transaction.")
	log.Printf("All addresses in stakeholders map before funding:")
	for addr, bal := range bc.ShardState.Stakeholders {
		log.Printf("  %s: %d", addr, bal)
	}

	genesisBalance, genesisExists := bc.ShardState.Stakeholders[genesisAddrStr]
	if !genesisExists {
		finalErr = fmt.Errorf("genesis address %s not found in stakeholders map", genesisAddrStr)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("Genesis address: %s, Balance: %d", genesisAddrStr, genesisBalance)

	amountValue := int64(req.Amount)

	if genesisBalance < amountValue {
		finalErr = fmt.Errorf("insufficient genesis funds: %d needed, %d available", amountValue, genesisBalance)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}

	// Update Stakeholders map (In-Memory)
	bc.ShardState.Stakeholders[genesisAddrStr] -= amountValue
	recipientBalance := bc.ShardState.Stakeholders[req.Address]
	bc.ShardState.Stakeholders[req.Address] = recipientBalance + amountValue
	log.Printf("Credited %d tokens (in-memory) to address %s, new balance: %d",
		amountValue, req.Address, bc.ShardState.Stakeholders[req.Address])

	// --- Create Funding UTXO ---
	fundingTxID := fmt.Sprintf("funding-%s-%d", req.Address, time.Now().UnixNano())
	fundingUtxoKey := fmt.Sprintf("ux-%d-%s-0", bc.ShardState.ShardID, fundingTxID)

	fundingUtxo := types.UTXO{
		ID:            fundingUtxoKey,
		TransactionID: fundingTxID,
		Index:         0,
		OwnerAddress:  req.Address,
		Amount:        req.Amount,
		IsSpent:       false,
	}

	log.Printf("DEBUG: Created funding UTXO with key: %s (shard %d)", fundingUtxoKey, bc.ShardState.ShardID)

	// --- Add Funding UTXO to In-Memory Map ---
	protoUtxo := convertTypesUTXOToProtoUTXO(fundingUtxo)
	bc.ShardState.UTXOs[fundingUtxoKey] = append(bc.ShardState.UTXOs[fundingUtxoKey], protoUtxo)
	log.Printf("DEBUG: Added funding UTXO %s to in-memory map", fundingUtxoKey)

	// --- Persist State Changes to Database using AddToBalance ---
	log.Printf("DEBUG: Persisting balance/UTXO updates to DB...")

	// CRITICAL FIX: Get the total number of shards for AddToBalance
	totalNumShards := bc.GetTotalNumShards() // You'll need to implement this method
	// If you don't have this method, you can hardcode it temporarily:
	// totalNumShards := 8 // or whatever your shard count is

	// 1. Update Genesis Balance in DB using AddToBalance (debit)
	genesisDebit := -amountValue // Negative amount to debit
	err = bc.ShardState.Database.AddToBalance(dbTxContext, genesisAddrStr, genesisDebit, totalNumShards)
	if err != nil {
		finalErr = fmt.Errorf("failed to debit genesis balance in DB: %v", err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("DEBUG: Debited %d from genesis address %s using AddToBalance", amountValue, genesisAddrStr)
	log.Printf("SUCCESS: Updated genesis balance for %s in DB", genesisAddrStr)

	// 2. Update Recipient Balance in DB using AddToBalance (credit)
	err = bc.ShardState.Database.AddToBalance(dbTxContext, req.Address, amountValue, totalNumShards)
	if err != nil {
		finalErr = fmt.Errorf("failed to credit recipient %s balance in DB: %v", req.Address, err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("DEBUG: Credited %d to recipient address %s using AddToBalance", amountValue, req.Address)
	log.Printf("SUCCESS: Updated recipient balance for %s in DB", req.Address)

	// 3. Add New Funding UTXO to DB
	err = bc.ShardState.Database.AddNewUTXO(dbTxContext, fundingUtxo, int(bc.ShardState.ShardID))
	if err != nil {
		finalErr = fmt.Errorf("failed to persist funding UTXO %s to DB: %v", fundingUtxoKey, err)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("DEBUG: [AddNewUTXO TX] Setting UTXO key: %s", fundingUtxoKey)
	log.Printf("SUCCESS: Persisted funding UTXO %s to DB", fundingUtxoKey)

	// --- Commit DB Transaction ---
	log.Printf("DEBUG: Committing DB transaction.")
	commitErr := bc.ShardState.Database.CommitTransaction(dbTxContext)
	if commitErr != nil {
		finalErr = fmt.Errorf("failed to commit funding DB transaction for %s: %v", req.Address, commitErr)
		log.Printf("ERROR: %v", finalErr)
		msg.ResponseCh <- types.Response{Error: finalErr}
		return
	}
	log.Printf("DEBUG: DB transaction committed successfully.")
	dbTxContext = nil // Prevent rollback by defer if commit was successful

	// --- Success ---
	log.Printf("Successfully funded address %s and created UTXO %s", req.Address, fundingUtxoKey)
	msg.ResponseCh <- types.Response{Data: true}
}
