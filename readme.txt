// to Start the app, 
// cd cmd
// go run main.go

Below is a textual representation of the data flow in your blockchain architecture, which can guide the creation of a visual DFD.

Level 1: Simplified Data Flow
Transaction Creation:

Users generate transactions, which include inputs, outputs, and a signature.
Each transaction is signed with the user's private key.
Transaction Broadcasting:

Signed transactions are broadcasted to the network's nodes.
Transaction Verification:

Nodes verify the transactions' signatures and check the validity of inputs using the UTXO set.
Block Formation:

Verified transactions are collected into a new block by a validator node.
Block Broadcasting:

The new block is broadcasted to the network for validation.
Block Validation:

Nodes validate the new block by checking transactions' validity and the block's hash.
Blockchain Update:

Once validated, the new block is added to the blockchain.
UTXOs are updated based on the transactions in the new block.
Level 2: Detailed Component Interaction
User Actions:

Users interact with the blockchain via wallet interfaces, creating transactions.
Node Processing:

Node receives and stores pending transactions.
Node participates in consensus protocols (if applicable) and block validation.
Transaction Processing:

Transaction objects are created and signed.
PublicKeyToAddress converts users' public keys to addresses.
CreateAndSignTransaction generates and signs a transaction.
SignTransaction signs the transaction data.
VerifyTransaction and VerifyTransactionSignature check the transaction's integrity.
Block Processing:

Blockchain manages the chain of blocks and validates new blocks.
AddBlock or similar functions add new validated blocks to the blockchain.
MerkleTree structures within blocks ensure data integrity.
Peer Networking:

AddPeer and DiscoverPeers manage node connections.
BroadcastTransaction and BroadcastBlock disseminate data across the network.
SyncBlockchain synchronizes the local blockchain with peers.
Sharding (if used):

Shard manages a subset of nodes and transactions for scalability.
AddNode, AssignNode, and RedistributeData facilitate shard operations.