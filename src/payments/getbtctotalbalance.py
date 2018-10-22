#!/usr/bin/env python

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import logging

logging.basicConfig()
logging.getLogger("BitcoinRPC").setLevel(logging.DEBUG)

rpc_user = "bitcoinuser"
rpc_password = "bitcoinpassword"

def get_balance():
        rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%(rpc_user, rpc_password))
        return rpc_connection.getbalance()

