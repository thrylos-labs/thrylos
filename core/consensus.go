package core

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
)

// Vote represents a vote cast by a validator for a specific block
type Vote struct {
	BlockHash []byte // Hash of the block being voted for
	Validator string // Address of the validator casting the vote
	Stake     int64  // Stake amount of the validator at the time of voting
}

const minStakeRequirement = 40 * 1e7 // 40 THRYLOS in nanoTHRYLOS

// VoteForBlock allows a node to cast a vote for a specific block
func (node *Node) VoteForBlock(block *Block) {
	stake, exists := node.Blockchain.Stakeholders[node.Address]
	if !exists || stake < minStakeRequirement {
		return // This node doesn't have enough stake to vote
	}

	vote := Vote{BlockHash: block.Hash, Validator: node.Address, Stake: stake}
	voteData, err := json.Marshal(vote)
	if err != nil {
		fmt.Println("Failed to serialize vote:", err)
		return
	}

	for _, peer := range node.Peers {
		http.Post(peer.Address+"/vote", "application/json", bytes.NewBuffer(voteData))
	}
}

// CountVotes tallies the votes for blocks from validators
func (node *Node) CountVotes() {
	majorityStake := node.Blockchain.TotalStake()/2 + 1
	voteStakes := make(map[string]int64)

	for _, vote := range node.Votes {
		hashStr := hex.EncodeToString(vote.BlockHash)
		voteStakes[hashStr] += vote.Stake
		if voteStakes[hashStr] >= majorityStake {
			var majorityBlock *Block
			for _, block := range node.Blockchain.Blocks {
				if bytes.Equal(block.Hash, vote.BlockHash) {
					majorityBlock = block
					break
				}
			}

			if majorityBlock != nil {
				node.BroadcastBlock(majorityBlock)
				node.Votes = []Vote{} // Clear votes
				break
			} else {
				log.Printf("Majority block with hash %x not found", vote.BlockHash)
			}
		}
	}
}

// TotalStake calculates the total stake from all stakeholders
func (bc *Blockchain) TotalStake() int64 {
	var total int64
	for _, stake := range bc.Stakeholders {
		total += stake
	}
	return total
}

// SecureRandomInt generates a cryptographically secure random integer
func SecureRandomInt(max int64) (int64, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int64(nBig.Int64()), nil
}

// SelectValidator chooses a validator based on stake weight
func (bc *Blockchain) SelectValidator() string {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	if len(bc.ActiveValidators) == 0 {
		fmt.Println("No active validators available.")
		return ""
	}

	var totalStake int64
	validatorStakes := make(map[string]int64)

	for _, validator := range bc.ActiveValidators {
		stake := bc.Stakeholders[validator]
		totalStake += stake
		validatorStakes[validator] = stake
	}

	if totalStake == 0 {
		fmt.Println("No stake available among active validators.")
		return ""
	}

	randStake, err := SecureRandomInt(totalStake)
	if err != nil {
		fmt.Println("Failed to generate secure random number:", err)
		return ""
	}

	for validator, stake := range validatorStakes {
		randStake -= stake
		if randStake < 0 {
			return validator
		}
	}

	return ""
}
