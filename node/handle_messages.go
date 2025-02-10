package node

// // handled throguh node messages to avoid import cycle errors
// func (node *Node) handleMessages() {
// 	for msg := range node.messageCh {
// 		switch msg.Type {
// 		case shared.GetUTXOs:
// 			node.handleGetUTXOs(msg)
// 		case shared.AddUTXO:
// 			node.handleAddUTXO(msg)
// 		case shared.UpdateState:
// 			node.handleUpdateState(msg)
// 		case shared.GetBalance:
// 			node.handleGetBalanceMessage(msg)
// 		case shared.ProcessBlock:
// 			node.handleProcessBlockMessage(msg)
// 		case shared.ValidateBlock:
// 			node.handleValidateBlockMessage(msg)
// 		case shared.GetStakingStats:
// 			node.handleGetStakingStatsMessage(msg)
// 		case shared.CreateStake:
// 			node.handleCreateStakeMessage(msg)
// 		}
// 	}
// }

// func (node *Node) handleGetUTXOs(msg shared.Message) {
// 	req := msg.Data.(shared.UTXORequest)
// 	utxos, err := node.blockchain.GetUTXOsForAddress(req.Address)
// 	msg.ResponseCh <- shared.Response{
// 		Data:  utxos,
// 		Error: err,
// 	}
// }

// func (node *Node) handleAddUTXO(msg shared.Message) {
// 	req := msg.Data.(shared.AddUTXORequest)
// 	err := node.Database.AddUTXO(req.UTXO)
// 	msg.ResponseCh <- shared.Response{
// 		Error: err,
// 	}
// }

// func (node *Node) handleUpdateState(msg shared.Message) {
// 	req := msg.Data.(shared.UpdateStateRequest)
// 	node.Blockchain.StateManager.UpdateState(req.Address, req.Balance, nil)
// 	msg.ResponseCh <- shared.Response{} // No error possible in current implementation
// }

// // // Individual message handlers
// func (node *Node) handleGetBalanceMessage(msg shared.Message) {
// 	address := msg.Data.(string)
// 	balance, err := node.BalanceManager.GetBalance(address)
// 	msg.ResponseCh <- shared.Response{
// 		Data:  balance,
// 		Error: err,
// 	}
// }

// func (node *Node) handleProcessBlockMessage(msg shared.Message) {
// 	block := msg.Data.(*shared.Block)
// 	err := node.ValidateAndVoteForBlock(block)
// 	msg.ResponseCh <- shared.Response{
// 		Error: err,
// 	}
// }

// func (node *Node) handleValidateBlockMessage(msg shared.Message) {
// 	block := msg.Data.(*shared.Block)
// 	err := node.ValidateAndVoteOnBlock(block)
// 	msg.ResponseCh <- shared.Response{
// 		Error: err,
// 	}
// }

// func (node *Node) handleGetStakingStatsMessage(msg shared.Message) {
// 	stats := node.GetStakingStats()
// 	msg.ResponseCh <- shared.Response{
// 		Data: stats,
// 	}
// }

// func (node *Node) handleCreateStakeMessage(msg shared.Message) {
// 	data := msg.Data.(map[string]interface{})
// 	address := data["address"].(string)
// 	amount := data["amount"].(int64)

// 	stake, err := node.CreateStake(address, amount)
// 	msg.ResponseCh <- shared.Response{
// 		Data:  stake,
// 		Error: err,
// 	}
// }
