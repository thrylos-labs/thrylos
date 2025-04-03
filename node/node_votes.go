package node

// For thrylos.Block
// For types.Vote, types.Block

// func (node *Node) BroadcastVote(validatorID string, blockNumber int32) error {
// 	vote := types.Vote{ // Changed from validator.Vote
// 		ValidatorID: validatorID,
// 		BlockNumber: blockNumber,
// 		Timestamp:   time.Now(),
// 		VoterNode:   node.Address,
// 	}

// 	// If this node is not the vote counter, send to the designated counter
// 	if !node.IsVoteCounter {
// 		// Send vote to specific vote counter node
// 		counterPeer, exists := node.Peers[node.VoteCounterAddress]
// 		if !exists {
// 			return fmt.Errorf("vote counter node not found in peers")
// 		}
// 		return counterPeer.SendVote(vote)
// 	}

// 	// If this is the vote counter node, process the vote
// 	node.VoteCounter.AddVote(vote)
// 	return nil
// }

// // Validate block and send vote
// func (node *Node) ValidateAndVoteOnBlock(block *thrylos.Block) error {
// 	// Validate the block
// 	if err := node.blockchain.VerifySignedBlock(block); err != nil {
// 		return fmt.Errorf("block validation failed: %v", err)
// 	}

// 	// If validation successful, send vote to counter node
// 	return node.BroadcastVote(block.Validator, block.Index)
// }

// func (node *Node) syncVotes() {
// 	for _, peer := range node.Peers {
// 		resp, err := http.Get(fmt.Sprintf("%s/votes", peer.Address))
// 		if err != nil {
// 			log.Printf("Failed to sync votes with peer %s: %v", peer.Address, err)
// 			continue
// 		}
// 		defer resp.Body.Close()

// 		var votes []types.Vote // Changed from validator.Vote
// 		if err := json.NewDecoder(resp.Body).Decode(&votes); err != nil {
// 			log.Printf("Failed to decode votes from peer %s: %v", peer.Address, err)
// 			continue
// 		}

// 		for _, vote := range votes {
// 			node.VoteCounter.AddVote(vote)
// 		}
// 	}
// }

// func (node *Node) ValidateAndVoteForBlock(block *types.Block) error {
// 	// Perform block validation
// 	if err := node.blockchain.VerifySignedBlock(block); err != nil {
// 		return fmt.Errorf("block validation failed: %v", err)
// 	}

// 	// Create vote with validation result
// 	vote := types.Vote{ // Changed from validator.Vote
// 		ValidatorID:    block.Validator,
// 		BlockNumber:    block.Index,
// 		BlockHash:      block.Hash,
// 		ValidationPass: true,
// 		Timestamp:      time.Now(),
// 		VoterNode:      node.Address,
// 	}

// 	// Send vote to designated counter node
// 	if err := node.sendVoteToCounter(vote); err != nil {
// 		return fmt.Errorf("failed to send vote to counter: %v", err)
// 	}

// 	return nil
// }

// func (node *Node) sendVoteToCounter(vote types.Vote) error { // Changed from validator.Vote
// 	if node.IsVoteCounter {
// 		// If this is the counter node, process locally
// 		return node.VoteCounter.AddVote(vote)
// 	}

// 	// Send to designated counter node
// 	voteData, err := json.Marshal(vote)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal vote: %v", err)
// 	}

// 	url := fmt.Sprintf("%s/vote", node.VoteCounterAddress)
// 	resp, err := http.Post(url, "application/json", bytes.NewBuffer(voteData))
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return fmt.Errorf("vote counter returned non-OK status: %d", resp.StatusCode)
// 	}

// 	return nil
// }

// func (node *Node) GetValidatorVoteStatus(validatorID string) int {
// 	return node.VoteCounter.GetVoteCount(validatorID)
// }
