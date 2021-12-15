from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
import algosdk as ak
from algosdk import mnemonic

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    g.session.add(Log(message=msg))
    g.session.commit()
    return


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    algo_sk, algo_pk = ak.account.generate_account()
    #my_mnemonic = mnemonic.from_private_key(algo_pk)
    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    #w3 = Web3()

    # TODO: Generate or read (using the mnemonic secret)
    # the ethereum public/private keys
    # done in gen_keys
    eth_sk = b'\xe61\x8e\xea\x80J(Z\xd2\xb8\x80\xdc\xbeo\xbf\xd3)\xa6\xdaj\xcf\\Ge\xb5\x9f\x95\xea~\xfe\x9c\xfd'
    eth_pk = '0x8bdA0E55eF0F817dBE3F70F404c9FeAA1f6D0Cb1'
    return eth_sk, eth_pk


def fill_order(order, txes=[]):
    # TODO:
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    order.timestamp = datetime.now()
    g.session.add(order)
    g.session.commit()
    # when execute the transaction, grant tx_id
    tx = {'amount': order.sell_amount, 'platform': order.sell_currency, 'receiver_pk': order.receiver_pk,
          'order_id': order.id, 'tx_id': None}
    txes.append(tx)

    orders = g.session.query(Order).filter(Order.filled == None).all()
    for order in orders:
        if (order.buy_currency == order.sell_currency and order.sell_currency == order.buy_currency and
                float(order.sell_amount) / float(order.buy_amount) > float(order.buy_amount) / float(order.sell_amount)):
            order.filled = datetime.now()
            order.counterparty_id = order.id
            order.counterparty = [order]
            g.session.commit()
            new_orders = {}
            new_orders['buy_amount'] = order.buy_amount - order.sell_amount
            new_orders['sell_amount'] = order.sell_amount - order.buy_amount
            new_orders['buy_currency'] = order.buy_currency
            new_orders['sell_currency'] = order.sell_currency
            new_orders['creator_id'] = order.id
            new_orders['sender_pk'] = order.sender_pk
            new_orders['receiver_pk'] = order.receiver_pk
            new_order = Order(**{i: new_orders[i] for i in new_orders})
            fill_order(new_order, txes)


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO:
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    send_tokens_algo(g.acl, algo_sk, algo_txes)
    for tx in algo_txes:
        tx_dict = {'platform': 'Algorand', 'receiver_pk': tx['receiver_pk'], 'order_id': tx['order_id'], 'tx_id': tx['tx_id']}
        tx = TX(**{i: tx_dict[i] for i in tx_dict})
        g.session.add(tx)
        g.session.commit()

    send_tokens_eth(g.w3, eth_sk, eth_txes)
    for tx in eth_txes:
        tx_dict = {'platform': 'Ethereum', 'receiver_pk': tx['receiver_pk'], 'order_id': tx['order_id'], 'tx_id': tx['tx_id']}
        tx = TX(**{i: tx_dict[i] for i in tx_dict})
        g.session.add(tx)
        g.session.commit()


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            eth_sk, eth_pk = get_eth_keys()
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            # Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here
        sig = content['sig']
        payload = content['payload']
        pk = payload['sender_pk']

        if payload['platform'] == 'Algorand':
            ifvalid_sign = algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk)
        elif payload['platform'] == 'Ethereum':
            eth_encoded_message = eth_account.messages.encode_defunct(text=json.dumps(payload))
            ifvalid_sign = (eth_account.Account.recover_message(eth_encoded_message, signature=sig) == pk)

        # 1. Check the signature
        if ifvalid_sign:
            payload['signature'] = sig
            order = Order(**{i: payload[i] for i in payload})
        # 2. Add the order to the table
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
            if order.sell_currency == "Ethereum":
                tx = g.w3.eth.get_transaction(payload['tx_id'])
                if tx is None:
                    return jsonify(False)
                if tx["value"] != order.sell_amount:
                    return jsonify(False)
            elif order.sell_currency == "Algorand":
                tx = indexer.search_transaction(txid=payload['tx_id'])
                if tx is None:
                    return jsonify(False)
                if tx.amt != order.sell_amount:
                    return jsonify(False)
            txes = []
            fill_order(order, txes)
             # 4. Execute the transactions
            execute_txes(txes)
            return jsonify(True)

        else:
            print('Cannot verify signature')
            log_message(payload)
            return jsonify(False)

        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk"]

    # Same as before
    # paste from the previous code
    orders = g.session.query(Order).filter().all()
    newList = []

    for i in orders:
        order = {}
        order['sender_pk'] = i.sender_pk
        order['receiver_pk'] = i.receiver_pk
        order['buy_currency'] = i.buy_currency
        order['sell_currency'] = i.sell_currency
        order['buy_amount'] = i.buy_amount
        order['sell_amount'] = i.sell_amount
        order['signature'] = i.signature
        newList.append(order)

    result = {}
    result['data'] = newList
    return jsonify(result)



if __name__ == '__main__':
    app.run(port='5002')