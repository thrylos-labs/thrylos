package node

// // // Hold the chain ID and then proviude a method to set it
// func (n *Node) SetChainID(chainID string) {
// 	n.chainID = chainID
// }

// func (n *Node) ConfirmBlock(blockNumber int32) {
// 	if !n.IsVoteCounter {
// 		return
// 	}

// 	// Broadcast confirmation to all nodes
// 	confirmation := struct {
// 		BlockNumber int32
// 		Confirmed   bool
// 	}{
// 		BlockNumber: blockNumber,
// 		Confirmed:   true,
// 	}

// 	n.BroadcastBlockConfirmation(confirmation)
// }

// func (node *Node) BroadcastBlockConfirmation(confirmation struct {
// 	BlockNumber int32
// 	Confirmed   bool
// }) {
// 	// Convert confirmation to JSON
// 	confirmationData, err := json.Marshal(confirmation)
// 	if err != nil {
// 		log.Printf("Failed to marshal block confirmation: %v", err)
// 		return
// 	}

// 	// Broadcast to all peers
// 	for _, peer := range node.Peers {
// 		url := fmt.Sprintf("%s/block-confirmation", peer.Address)
// 		resp, err := http.Post(url, "application/json", bytes.NewBuffer(confirmationData))
// 		if err != nil {
// 			log.Printf("Failed to send confirmation to peer %s: %v", peer.Address, err)
// 			continue
// 		}
// 		resp.Body.Close()
// 	}

// 	log.Printf("Block %d confirmation broadcast to all peers", confirmation.BlockNumber)
// }
