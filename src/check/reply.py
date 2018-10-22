from src.cryptography import address, messages, encrypt
from hashlib import sha256
import time
import sqlite3 as sql
import requests
import os

def create_payload(sender,payment_type,address_type,address,amount,additional2,product_hash,quantity):
	try:
		additional1 = "REPLY"
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
		transaction_on_success = os.urandom(32)
		transaction_on_success = transaction_on_success.encode("hex")
		transaction_on_success = sha256(transaction_on_success.rstrip()).hexdigest()
		data = address + "," + amount + "," + transaction_on_success
		data = encrypt.encryptWithRSAKey(key, data)
		timestamp = str(int(time.time()))
		final = "TREEPAY" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
		tx_hash = sha256(final.rstrip()).hexdigest()
		signature = messages.sign_message(private_key_hex, tx_hash)
		payload = "TREEPAY" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
		time_generated = str(int(time.time()))
		cur.execute('INSERT INTO addresses (type,identifier,ticker,address,amount,time_generated,transaction_on_success) VALUES (?,?,?,?,?,?,?)', (payment_type,sender,address_type,address,amount,time_generated,transaction_on_success))
		con.commit()
		cur.execute('INSERT INTO messages (type,sender,address,times,refers_to,transaction_on_success,time_generated) VALUES (?,?,?,?,?,?,?)', (payment_type,sender,address,quantity,product_hash,transaction_on_success,time_generated))
		con.commit()
		return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def send_reply(sender,payment_type,address_type,address,amount,additional2,product_hash,quantity):
	try:
		payload = create_payload(sender,payment_type,address_type,address,amount,additional2,product_hash,quantity)
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
