package node

// // // handled throguh node messages to avoid import cycle errors
// func (node *Node) handleMessages() {
// 	for msg := range node.messageCh {
// 		switch msg.Type {
// 		case types.GetUTXOs:
// 			node.handleGetUTXOs(msg)
// 		case types.AddUTXO:
// 			node.handleAddUTXO(msg)
// 		case types.UpdateState:
// 			node.handleUpdateState(msg)
// 		case types.GetBalance:
// 			node.handleGetBalanceMessage(msg)
// 		case types.ProcessBlock:
// 			node.handleProcessBlockMessage(msg)
// 		case types.ValidateBlock:
// 			node.handleValidateBlockMessage(msg)
// 		case types.GetStakingStats:
// 			node.handleGetStakingStatsMessage(msg)
// 		case types.CreateStake:
// 			node.handleCreateStakeMessage(msg)
// 		}
// 	}
// }

// func (node *Node) handleGetUTXOs(msg types.Message) {
// 	req := msg.Data.(types.UTXORequest)
// 	utxos, err := node.blockchain.GetUTXOsForAddress(req.Address)
// 	msg.ResponseCh <- types.Response{
// 		Data:  utxos,
// 		Error: err,
// 	}
// }

// func (node *Node) handleAddUTXO(msg types.Message) {
// 	req := msg.Data.(types.AddUTXORequest)
// 	err := node.Database.AddUTXO(req.UTXO)
// 	msg.ResponseCh <- types.Response{
// 		Error: err,
// 	}
// }

// func (node *Node) handleUpdateState(msg types.Message) {
// 	req := msg.Data.(types.UpdateStateRequest)
// 	node.Blockchain.StateManager.UpdateState(req.Address, req.Balance, nil)
// 	msg.ResponseCh <- types.Response{} // No error possible in current implementation
// }

// // // Individual message handlers
// func (node *Node) handleGetBalanceMessage(msg types.Message) {
// 	address := msg.Data.(string)
// 	balance, err := node.BalanceManager.GetBalance(address)
// 	msg.ResponseCh <- types.Response{
// 		Data:  balance,
// 		Error: err,
// 	}
// }

// func (node *Node) handleProcessBlockMessage(msg types.Message) {
// 	block := msg.Data.(*types.Block)
// 	err := node.ValidateAndVoteForBlock(block)
// 	msg.ResponseCh <- types.Response{
// 		Error: err,
// 	}
// }

// func (node *Node) handleValidateBlockMessage(msg types.Message) {
// 	block := msg.Data.(*types.Block)
// 	err := node.ValidateAndVoteOnBlock(block)
// 	msg.ResponseCh <- types.Response{
// 		Error: err,
// 	}
// }

// func (node *Node) handleGetStakingStatsMessage(msg types.Message) {
// 	stats := node.GetStakingStats()
// 	msg.ResponseCh <- types.Response{
// 		Data: stats,
// 	}
// }

// func (node *Node) handleCreateStakeMessage(msg types.Message) {
// 	data := msg.Data.(map[string]interface{})
// 	address := data["address"].(string)
// 	amount := data["amount"].(int64)

// 	stake, err := node.CreateStake(address, amount)
// 	msg.ResponseCh <- types.Response{
// 		Data:  stake,
// 		Error: err,
// 	}
// }
