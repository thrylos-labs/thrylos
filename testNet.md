To run the testnet in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/thrylosnode

Then run the encryption: 
export AES_KEY_ENV_VAR='b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I='

By starting with new addresses, you can test how the system handles initialization, empty blocks, new transactions, and other edge cases more effectively.

then:
go run main.go --address=localhost:8080 --data=./node_data --testnet

Update the secure_accounts.json with the new addresses and info from the testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/clisigner

Sign the transaction: 

go run cli_signer.go -address="8cead27c2c53f5669b2943213f38d21dda82ae851fc51a767aa74f0b637fddbf" -transaction='{"sender": "8cead27c2c53f5669b2943213f38d21dda82ae851fc51a767aa74f0b637fddbf", "recipient": "b2aed28f8fe2ca4ff6d427470a8a0d32f711b2ae18bff1e83d68c4049a45cbcf", "amount": 100}'

[
    {
        "Address": "8cead27c2c53f5669b2943213f38d21dda82ae851fc51a767aa74f0b637fddbf",
        "PrivateKey": "qE7TwYtHetbur7gkAsWFo0Aa91nCMqHdTE6KCBNCCKcP4rKPPaJl7/q8/ARH/Go8HLP56xlGfieUrUoXFzE8nA==",
        "PublicKey": "0fe2b28f3da265effabcfc0447fc6a3c1cb3f9eb19467e2794ad4a1717313c9c"
    },
    {
        "Address": "b2aed28f8fe2ca4ff6d427470a8a0d32f711b2ae18bff1e83d68c4049a45cbcf",
        "PrivateKey": "tOMmH7chRRkXi4d4/PyNnUvPCsrv29HMAX+fMH7kC7K48d/PdLGYCqBpFe0Eky4jKF9PBjlG5Wd+8gg/IjeJNA==",
        "PublicKey": "b8f1dfcf74b1980aa06915ed04932e23285f4f063946e5677ef2083f22378934"
    }
]

Retreive the public key first:

 Before attempting another transaction submission, directly test the retrieval function for the public key in your code to confirm that it can indeed find and return the correct key. This can help isolate the issue:


Sugmit the transaction using Curl:

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "8cead27c2c53f5669b2943213f38d21dda82ae851fc51a767aa74f0b637fddbf",
    "recipient": "b2aed28f8fe2ca4ff6d427470a8a0d32f711b2ae18bff1e83d68c4049a45cbcf",
    "amount": 100,
    "signature": "55qEsDuiChWA66Cyiq72FxBf5NWhnMTB0a4LXff2NKnzlEq1c/TFMdYXBTjT3QwfCWJ0Cs/XcRQhHP1OepbdDw==",
    "inputs": [
        {
            "transactionId": "genesis_8cead27c2c53f5669b2943213f38d21dda82ae851fc51a767aa74f0b637fddbf",
            "outputIndex": 0,
            "signature": "55qEsDuiChWA66Cyiq72FxBf5NWhnMTB0a4LXff2NKnzlEq1c/TFMdYXBTjT3QwfCWJ0Cs/XcRQhHP1OepbdDw=="
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