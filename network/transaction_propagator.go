package network

// The TransactionPropagator ensures that when a new transaction is added to the blockchain,
// all validators (network participants who verify transactions) receive a copy of it.
// This keeps the network in sync by making sure everyone is working with the same transactions.

// func NewTransactionPropagator(bc types.BlockchainInterface) *types.TransactionPropagator {
// 	return &types.TransactionPropagator{
// 		blockchain: bc,
// 	}
// }

// func (tp *types.TransactionPropagator) PropagateTransaction(tx *thrylos.Transaction) error {
// 	tp.mu.Lock()
// 	defer tp.mu.Unlock()

// 	// Get active validators using the interface method
// 	validators := tp.blockchain.GetActiveValidators()
// 	if len(validators) == 0 {
// 		return fmt.Errorf("no active validators")
// 	}

// 	// Simple propagation to each validator
// 	for _, validatorAddr := range validators {
// 		if err := tp.sendToValidator(tx, validatorAddr); err != nil {
// 			log.Printf("Failed to propagate to validator %s: %v", validatorAddr, err)
// 			continue
// 		}
// 		log.Printf("Transaction %s propagated to validator %s", tx.Id, validatorAddr)
// 	}

// 	return nil
// }

// // It needs to send transaction to the other nodes

// func (tp *types.TransactionPropagator) sendToValidator(tx *thrylos.Transaction, validatorAddr string) error {
// 	// Add transaction to validator's pending pool
// 	if err := tp.blockchain.AddPendingTransaction(tx); err != nil {
// 		return fmt.Errorf("failed to add to pending pool: %v", err)
// 	}
// 	return nil
// }
