"""Deploy the FileStorage contract using Web3.py

This script compiles the Solidity contract using solcx and deploys it to the configured Ethereum node.
Requires:
- pip install py-solc-x web3
"""
import os
import json
from solcx import compile_standard, install_solc
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

ETH_NODE_ENDPOINT = os.getenv('ETH_NODE_ENDPOINT')
ETH_ACCOUNT_ADDRESS = os.getenv('ETH_ACCOUNT_ADDRESS')
ETH_PRIVATE_KEY = os.getenv('ETH_PRIVATE_KEY')

if not all([ETH_NODE_ENDPOINT, ETH_ACCOUNT_ADDRESS, ETH_PRIVATE_KEY]):
    raise SystemExit('Missing Ethereum configuration in environment')

with open('../contracts/FileStorage.sol', 'r') as f:
    source = f.read()

install_solc('0.8.0')

compiled = compile_standard({
    'language': 'Solidity',
    'sources': {'FileStorage.sol': {'content': source}},
    'settings': {
        'outputSelection': {
            '*': {
                '*': ['abi', 'metadata', 'evm.bytecode', 'evm.sourceMap']
            }
        }
    }
}, solc_version='0.8.0')

bytecode = compiled['contracts']['FileStorage.sol']['FileStorage']['evm']['bytecode']['object']
abi = compiled['contracts']['FileStorage.sol']['FileStorage']['abi']

w3 = Web3(Web3.HTTPProvider(ETH_NODE_ENDPOINT))
chain_id = w3.eth.chain_id
acct = w3.eth.account.from_key(ETH_PRIVATE_KEY)

FileStorage = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce = w3.eth.get_transaction_count(acct.address)

transaction = FileStorage.constructor().build_transaction({
    'chainId': chain_id,
    'from': acct.address,
    'nonce': nonce,
    'gasPrice': w3.eth.gas_price,
})

signed_txn = acct.sign_transaction(transaction)

tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
print(f"Deploy transaction sent: {tx_hash.hex()}")

print("Waiting for receipt...")
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Contract deployed at address: {receipt.contractAddress}")

os.makedirs('../build', exist_ok=True)
with open('../build/FileStorage_abi.json', 'w') as f:
    json.dump(abi, f)
with open('../build/FileStorage_address.txt', 'w') as f:
    f.write(receipt.contractAddress)

print('Deployment complete')
