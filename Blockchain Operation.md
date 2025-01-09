
## Blockchain Operation Flowchart


## 1. Initialization

Nodes initialize with configurations, load environment variables, and set up necessary cryptographic parameters (like AES and RSA keys).
The blockchain database (BlockchainDB) initializes, setting up the storage structures for transactions, blocks, UTXOs, and keys.

## 2. Key Generation and Management

Generate RSA and MLDSA44 key pairs for transaction signing and encryption.
Public keys are stored and retrieved from the database, providing mechanisms to verify identities and signatures.

## 3. Transaction Creation

Transactions are created with inputs, outputs, and optional metadata.
Transaction data may be encrypted using AES for confidentiality, particularly for sensitive components like transaction inputs and outputs.

## 4. Transaction Signing

Transactions are signed using the private keys (MLDSA44 or RSA), ensuring non-repudiation and integrity.
The system supports batch signing for efficiency in processing multiple transactions.


## 5. Transaction Verification

Transactions are verified by checking digital signatures, ensuring they match the public keys and the transaction data hasn't been tampered with.
Additional checks include validating the balance of UTXOs to ensure no double-spending and verifying that the inputs match the outputs (no creation of value out of thin air).

## 6. Block creation

Transactions are grouped into blocks.
A cryptographic hash (using BLAKE2b algorithm) of the block is computed to ensure integrity. This hash includes transactions, timestamps, and the previous block’s hash, linking blocks securely.

## 7. Blockchain Consensus

Blocks are broadcast to other nodes in the network.
Nodes validate new blocks by verifying the block's hash, the validity of transactions within it, and the blockchain's rules.

## 8. Blockchain Synchronization

Nodes regularly synchronize the blockchain with peers to maintain consistency across the network.
This includes fetching and validating blocks from peers and updating the local blockchain if the peer's blockchain is longer or has diverged.

## 9. UTXO Management

UTXOs are updated with each transaction: new UTXOs are created for transaction outputs, and inputs are marked as spent.
The system maintains a database of UTXOs, which are crucial for determining the balance of addresses and the validity of new transactions.


## 10. Data Encryption and Decryption

Data stored in the blockchain database is encrypted using symmetric (AES) and asymmetric (RSA) cryptography to protect sensitive transaction details.
Encrypted data is decrypted when needed for processing, using the appropriate cryptographic keys.

## 11. Database Operations

All blockchain components (blocks, transactions, UTXOs, and keys) are stored in a structured database.
Database operations include inserting, updating, and retrieving data, with a focus on performance and integrity.

## 12. APIs and Interfaces

The blockchain exposes various functions through interfaces, allowing operations like retrieving balances, sending transactions, and managing keys.
These functions are critical for building applications on top of the blockchain, such as wallets or decentralized apps.