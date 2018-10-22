from src.cryptography import address, messages
from hashlib import sha256
import time
import sqlite3 as sql
import requests

def check_payload(payload):
	details = payload.split(",")
	if len(details) == 10:
		operation = details[0]
		sender = details[1]
		receiver = details[2]
                additional3 = details[6]
                Address = address.keyToAddr(additional3,sender)
                if Address != sender:
			return sender + "," + False
		if len(sender) < 36 or len(receiver) < 36 or len(sender) > 50 or len(receiver) > 50:
			return sender + "," + False
		timestamp = str(int(float(details[3])))
		time_now = time.time()
		additional1 = details[4]
		additional2 = details[5]
		data = details[7]
		transaction_hash = details[8]
		final = operation + ":" + sender + ":" + receiver + ":" + str(timestamp) + ":" + additional1 + ":" + additional2 + ":" + additional3 + ":" + data
		TX_hash = sha256(final.rstrip()).hexdigest()
		if TX_hash == transaction_hash:
			signature = details[-1]
			final = TX_hash
			prove_ownership = messages.verify_message(additional3, signature, final)
			if prove_ownership == True:
				return "True,"+data
			else:
				return "False,False"
		else:
			return "False,False"
	else:
		return "False,False"

def create_payload(account):
	try:
		additional2 = "TREEPAY".encode("hex")
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		cur.execute('SELECT * FROM keys WHERE identifier=? ORDER BY time_generated DESC LIMIT 1', (account,))
		keys = cur.fetchall()
		public_key = keys[-1]["public_key"]
		data = public_key
		data = data.encode("hex")
		timestamp = str(int(time.time()))
		final = "OSP" + ":" + account + ":" + account + ":" + timestamp + ":" + "None" + ":" + additional2 + ":" + public_key_hex + ":" + data
		tx_hash = sha256(final.rstrip()).hexdigest()
		signature = messages.sign_message(private_key_hex, tx_hash)
		payload = "OSP" + "," + account + "," + account + "," + timestamp + "," + "None" + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
		return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def online_status(account):
	try:
		payload = create_payload(account)
		if payload == False:
			return
		return_data = requests.post("http://127.0.0.1:10000/data/pool/new", data=payload)
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
