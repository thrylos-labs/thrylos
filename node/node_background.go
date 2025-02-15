package node

import (
	"log"

	"github.com/thrylos-labs/thrylos/consensus/processor"
)

// Essential background tasks and initialization
func (node *Node) Shutdown() error {
	// Keep essential cleanup
	close(node.messageCh)

	/* Optional cleanup commented out
	   if node.blockProducer != nil {
	       node.blockProducer.Stop()
	   }
	*/
	return nil
}

// StartBackgroundTasks now only includes essential background processes
func (node *Node) StartBackgroundTasks() {
	/* Optional background tasks commented out
	   // Peer discovery
	   // tickerDiscoverPeers := time.NewTicker(10 * time.Minute)
	   // go func() {
	   //     for {
	   //         select {
	   //         case <-tickerDiscoverPeers.C:
	   //             network.DiscoverPeers()
	   //         }
	   //     }
	   // }()

	   // Vote synchronization
	   // tickerVoteSync := time.NewTicker(30 * time.Second)
	   // go func() {
	   //     for {
	   //         select {
	   //         case <-tickerVoteSync.C:
	   //             node.syncVotes()
	   //         }
	   //     }
	   // }()
	*/
}

/* Optional tasks commented out for future implementation
func (node *Node) startStakingTasks() {
    ticker := time.NewTicker(24 * time.Hour)
    for {
        select {
        case <-ticker.C:
            if err := node.StakingService.DistributeRewards(); err != nil {
                log.Printf("Error distributing staking rewards: %v", err)
            }
        }
    }
}
*/

// Keep only essential processor initialization
func (n *Node) InitializeProcessors() {
	log.Printf("Initializing essential node processors...")

	// Initialize DAG Manager - essential for transaction processing
	n.DAGManager = processor.NewDAGManager()
	log.Printf("DAG manager initialized")

	/* Optional processors commented out
	   // n.ModernProcessor = processor.NewModernProcessor()
	   // n.ModernProcessor.Start()
	   // log.Printf("Modern processor initialized and started")
	*/

	log.Printf("Essential node processors initialization complete")
}
