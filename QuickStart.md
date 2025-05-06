## Quick Start

Jump into action with these simple steps:

1.  **Set Up**: Clone the repository to your local machine.
2.  **Generate AES Key**: *(Add instructions here or link to how)*. This key is crucial for encrypting sensitive data. Keep it safe!
3.  **Generate Genesis PrivateKey**: *(Add instructions here or link to how)*. This key is crucial for encrypting sensitive data. Keep it safe!
4.  **Create a `.env` file**: Copy the example below into a file named `.env` in the project's root directory. **Modify the placeholder values.**

    ```dotenv
    # Environment: 'development' or 'production'
    ENV=development

    # Network Addresses (adjust ports if needed)
    HTTP_NODE_ADDRESS=:50051 # Address for HTTP API
    GRPC_NODE_ADDRESS=:50052 # Address for gRPC API
    WS_ADDRESS=:8080       # Address for WebSocket connections

    # Peer Discovery (Optional: Add comma-separated peer multiaddrs if known)
    # Example: PEERS=/ip4/192.168.1.100/tcp/4001/p2p/QmPeerID1,/ip4/[another.peer.com/tcp/4001/p2p/QmPeerID2](https://another.peer.com/tcp/4001/p2p/QmPeerID2)
    PEERS=

    # Domain Name (if applicable, for external access/identity)
    DOMAIN_NAME=node.thrylos.org # Or leave blank if using SERVER_HOST or localhost

    # Server Host (alternative identity if DOMAIN_NAME is not set)
    SERVER_HOST=localhost # Or your server's IP/hostname

    # --- Critical Configuration ---

    # Blockchain Data Directory:
    # Stores all blockchain data (blocks, state).
    # Deleting this directory RESETS the node and requires a resync.
    # You can change this path if desired.
    DATA_DIR=./thrylos_data

    # AES Encryption Key:
    # Replace XXXXXXXXX with the Base64-encoded AES key you generated.
    AES_KEY_ENV_VAR=XXXXXXXXX # Example: bMQaGAB/pR+mldRnNGF1tH9usxn02rc+9Wx6jiFckqo=

    # Genesis Account Address:
    # Replace XXXXXXXXX with the designated genesis account address for the network.
    # This account usually holds the initial token supply.
    GENESIS_ACCOUNT=XXXXXXXXX # Example: tl11d26lhajjmg2xw95u66xathy7sge36t83zyfvwq

    # --- Other Settings ---

    # Use Testnet configuration (true/false)
    TESTNET=true

    # URL for the gas estimation API endpoint
    # Ensure this matches your HTTP_NODE_ADDRESS unless using an external service
    GAS_ESTIMATE_URL=http://localhost:50051/estimate-gas

    # Use SSL/TLS (true/false) - Typically false for development
    USE_SSL=false
    ```

4.  **Run the Node**:
    * **Easy Way:** Execute `./run_thrylos.sh` in your terminal. This script should set up the environment and run the node.
    * **Manual Way:**
        * Navigate: `cd cmd/thrylos`
        * Run: `go run .` (The `.env` file should be loaded automatically by your `main` function)

**Important:** Deleting the directory specified in `DATA_DIR` (default is `./thrylos_data`) will wipe all local blockchain data, account balances managed by this node, and require starting from scratch or resyncing from peers.