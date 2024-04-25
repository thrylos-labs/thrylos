To run the testnet in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/thrylosnode

By starting with new addresses, you can test how the system handles initialization, empty blocks, new transactions, and other edge cases more effectively.

then:
go run main.go --address=localhost:8080 --data=./node_data --testnet

Update the secure_accounts.json with the new addresses and info from the testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/clisigner

Sign the transaction: 

go run cli_signer.go -address="bef445733a165742b6a7a3d5125ee28b60a0777f5c2c0c5bb7e3327f81d8cac3" -transaction='{"sender": "bef445733a165742b6a7a3d5125ee28b60a0777f5c2c0c5bb7e3327f81d8cac3", "recipient": "140650119bd130250fbd9b75e84604f13ecaee05cbb15f783d25390b2ab9b23e", "amount": 100}'

[
    {
        "Address": "bef445733a165742b6a7a3d5125ee28b60a0777f5c2c0c5bb7e3327f81d8cac3",
        "PrivateKey": "7KuBYoufwg2MmQGcHL5LptRIqRMEb+H0gxE/3jLQf68bKDHMO22ssry+j3EzuVW0RrBt/oEzsJEoOer2t6fdrg==",
        "PublicKey": "1b2831cc3b6dacb2bcbe8f7133b955b446b06dfe8133b0912839eaf6b7a7ddae"
    },
    {
        "Address": "140650119bd130250fbd9b75e84604f13ecaee05cbb15f783d25390b2ab9b23e",
        "PrivateKey": "6m0IuJ+BkcwIALgYLbXkkrKUGyOVli8PnQl2oa3Te941vdIaAEHa8h06ZsIg0MBPc5jHc/VZTejmu2dmdLsM6A==",
        "PublicKey": "35bdd21a0041daf21d3a66c220d0c04f7398c773f5594de8e6bb676674bb0ce8"
    }
]




Retreive the public key first:

 Before attempting another transaction submission, directly test the retrieval function for the public key in your code to confirm that it can indeed find and return the correct key. This can help isolate the issue:


Sugmit the transaction using Curl:

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "bef445733a165742b6a7a3d5125ee28b60a0777f5c2c0c5bb7e3327f81d8cac3",
    "recipient": "140650119bd130250fbd9b75e84604f13ecaee05cbb15f783d25390b2ab9b23e",
    "amount": 100,
    "signature": "Z1vmLjcVS2uCA0NzMl9YCcLY4kUihQm+dgkPt9ODgiow2d+uhJI/6gum4fnov20mzV4ZAH2wyzYjpLvoV9rNBQ==",
    "inputs": [
        {
            "transactionId": "bef445733a165742b6a7a3d5125ee28b60a0777f5c2c0c5bb7e3327f81d8cac3",
            "outputIndex": 0,
            "signature": "Z1vmLjcVS2uCA0NzMl9YCcLY4kUihQm+dgkPt9ODgiow2d+uhJI/6gum4fnov20mzV4ZAH2wyzYjpLvoV9rNBQ=="
        }
    ]
}' http://localhost:8080/submit-transaction



Summary
Generate Transaction Data: Define the essential attributes of your transaction, like sender, recipient, and amount.
Sign the Transaction: Use your CLI utility to sign the transaction data, generating a digital signature.
Submit the Transaction: Send the signed transaction to your blockchain network for processing.



curl -X POST http://localhost:8080/submit-transaction \
-H "Content-Type: application/json" \
-d '{
    "inputs": [
        {
            "previousTx": "abcd1234",  # Replace with the actual transaction ID from your blockchain
            "index": 0,
            "signature": "OerEAtzxvz6Lpp3BUqhIpjGPmWRfrQ39hsyi+rk+C2EChXQvFPshbrXSIWnu5soDgle3yem8LGe6mRrx4nZGCQ=="  
        }
    ],
    "outputs": [
        {
            "amount": 100,
            "address": "276b3b8a5fa2e9bfba6c9c535440e13906ba2ad0aa45e8ffea398cd13f564515"
        }
    ],
    "sender": "83bd6c7abd525db141737207aa170c539581b57685158512e6ca78da463bf801",
    "recipient": "276b3b8a5fa2e9bfba6c9c535440e13906ba2ad0aa45e8ffea398cd13f564515",
    "amount": 100,
    "signature": "OerEAtzxvz6Lpp3BUqhIpjGPmWRfrQ39hsyi+rk+C2EChXQvFPshbrXSIWnu5soDgle3yem8LGe6mRrx4nZGCQ=="  
}