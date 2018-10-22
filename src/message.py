from src.cryptography import address, messages, encrypt
from hashlib import sha256
import time
import sqlite3 as sql
import requests

def create_payload(sender,transaction_on_success,message):
	try:
		additional1 = "MESSAGE"
		additional2 = transaction_on_success
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM accounts')
		accounts = cur.fetchall()
		account = accounts[0]["identifier"]
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
		result = cur.fetchall()
		if len(result) == 1:
			key = result[0]["EncryptionKey"]
		else:
			requests.post("http://127.0.0.1:10000/user/search", data=sender)
			return "User is offline"
		data = message
		data = encrypt.encryptWithRSAKey(key, data)
		timestamp = str(int(time.time()))
		final = "TREEPAY" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
		tx_hash = sha256(final.rstrip()).hexdigest()
		signature = messages.sign_message(private_key_hex, tx_hash)
		payload = "TREEPAY" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
		return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def new_message(sender,transaction_on_success,message):
	try:
		payload = create_payload(sender,transaction_on_success,message)
		if sender in payload:
			return_data = requests.post("http://127.0.0.1:10000/data/pool/new", data=payload)
			return True
		else:
			return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass
