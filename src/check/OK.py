from src.cryptography import address, messages
from hashlib import sha256
import time
import sqlite3 as sql
import requests

def create_payload(sender):
	try:
		additional1 = "OK"
		additional2 = "None"
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM accounts')
		accounts = cur.fetchall()
		account = accounts[0]["identifier"]
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		data = "None"
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

def send_OK(sender):
	try:
		payload = create_payload(sender)
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
