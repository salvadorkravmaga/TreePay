#!/usr/bin/env python

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import logging

logging.basicConfig()
logging.getLogger("BitcoinRPC").setLevel(logging.DEBUG)

rpc_user = "litecoin"
rpc_password = "litecoin"

def get_address():
        rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:9332"%(rpc_user, rpc_password))
        return rpc_connection.getnewaddress()
