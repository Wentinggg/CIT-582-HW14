#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3

if __name__ == '__main__':
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct, mnemonic_secret = w3.eth.account.create_with_mnemonic()
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk, eth_sk = acct._address, acct._private_key

    print("eth secret key:", eth_sk)
    print("eth public key", eth_pk)

