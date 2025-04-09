package chain

import (
	"fmt"
	"log"

	// Adjust the path to match your project structure

	"github.com/thrylos-labs/thrylos/types"
)

func (bc *BlockchainImpl) HandleFundNewAddress(msg types.Message) {
	mapAddress := fmt.Sprintf("%p", &bc.Blockchain.Stakeholders)
	log.Printf("DEBUG: HandleFundNewAddress using stakeholders map at address %s", mapAddress)
	log.Println("Handling FundNewAddress message")

	req, ok := msg.Data.(types.FundAddressRequest)
	if !ok {
		log.Println("Invalid fund request format")
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("invalid fund request format")}
		return
	}

	genesisAddr, _ := bc.Blockchain.GenesisAccount.PublicKey().Address()

	// Lock before reading the balance
	bc.Blockchain.Mu.Lock()

	log.Printf("All addresses in stakeholders map before funding:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf(" %s: %d", addr, bal)
	}

	genesisBalance := bc.Blockchain.Stakeholders[genesisAddr.String()]
	log.Printf("Genesis address: %s, Balance: %d", genesisAddr.String(), genesisBalance)

	// Define amountValue FIRST
	amountValue := int64(req.Amount)

	if genesisBalance < amountValue {
		bc.Blockchain.Mu.Unlock() // Don't forget to unlock if returning early
		log.Printf("Insufficient genesis funds: %d nanoTHRYLOS", genesisBalance)
		msg.ResponseCh <- types.Response{Error: fmt.Errorf("insufficient genesis funds")}
		return
	}

	// Record balances before changes for verification
	beforeGenesisBalance := bc.Blockchain.Stakeholders[genesisAddr.String()]

	// Update the genesis balance
	bc.Blockchain.Stakeholders[genesisAddr.String()] -= amountValue
	afterGenesisBalance := bc.Blockchain.Stakeholders[genesisAddr.String()]

	// Credit the tokens to the recipient address - MOVED HERE AFTER amountValue is defined
	_, exists := bc.Blockchain.Stakeholders[req.Address]
	if exists {
		bc.Blockchain.Stakeholders[req.Address] += amountValue
	} else {
		bc.Blockchain.Stakeholders[req.Address] = amountValue
	}
	log.Printf("Credited %d tokens to address %s, new balance: %d",
		amountValue, req.Address, bc.Blockchain.Stakeholders[req.Address])

	// Verify the deduction worked
	if beforeGenesisBalance == afterGenesisBalance {
		log.Printf("ERROR: Genesis balance did not change! Before: %d, After: %d",
			beforeGenesisBalance, afterGenesisBalance)
	}

	// Rest of your transaction and UTXO handling...
	bc.Blockchain.Mu.Unlock() // Unlock before database operations

	// Re-lock for the final verification check
	bc.Blockchain.Mu.Lock()
	finalGenesisBalance := bc.Blockchain.Stakeholders[genesisAddr.String()]
	if finalGenesisBalance != afterGenesisBalance {
		log.Printf("WARNING: Genesis balance changed again! After update: %d, Final check: %d",
			afterGenesisBalance, finalGenesisBalance)
	}

	log.Printf("Final addresses in stakeholders map after all operations:")
	for addr, bal := range bc.Blockchain.Stakeholders {
		log.Printf(" %s: %d", addr, bal)
	}
	bc.Blockchain.Mu.Unlock()

	// Persist the balance changes to the database
	var err error
	err = bc.Blockchain.Database.UpdateBalance(genesisAddr.String(), afterGenesisBalance)
	if err != nil {
		log.Printf("Failed to update genesis balance in database: %v", err)
	}

	// Also persist the recipient's balance
	err = bc.Blockchain.Database.UpdateBalance(req.Address, bc.Blockchain.Stakeholders[req.Address])
	if err != nil {
		log.Printf("Failed to update recipient balance in database: %v", err)
	}

	msg.ResponseCh <- types.Response{Data: true}
}
