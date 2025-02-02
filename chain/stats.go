package chain

type BlockchainStats struct {
	NumberOfBlocks       int   `json:"number_of_blocks"`
	NumberOfTransactions int   `json:"number_of_transactions"`
	TotalStake           int64 `json:"total_stake"`
	NumberOfPeers        int   `json:"number_of_peers"`
}

// Stats collector for the blockchain
type StatsCollector struct {
	blockchain *Blockchain
}

func NewStatsCollector(bc *Blockchain) *StatsCollector {
	return &StatsCollector{
		blockchain: bc,
	}
}

func (sc *StatsCollector) GetBlockStats() (int, int) {
	blocks := len(sc.blockchain.Blocks)
	txCount := 0
	for _, block := range sc.blockchain.Blocks {
		txCount += len(block.Transactions)
	}
	return blocks, txCount
}

// func (sc *StatsCollector) GetTotalStake() int64 {
// 	return sc.blockchain.TotalStake()
// }
