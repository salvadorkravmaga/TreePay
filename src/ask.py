from src.cryptography import address, messages, encrypt
from src import encryption
from hashlib import sha256
import time
import sqlite3 as sql
import requests

def create_payload(payment_type,product_hash,times,address_type,sender,unique_id):
	try:
		additional1 = "ASK"
		additional2 = unique_id
		times = str(times)
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
		if payment_type == "PURCHASE":
			data = payment_type + "," + product_hash + "," + times + "," + address_type
		elif payment_type == "DONATE":
			data = payment_type + "," + address_type
		else:
			return False
		data = encrypt.encryptWithRSAKey(key, data)
		timestamp = str(int(time.time()))
		final = "TREEPAY" + ":" + account + ":" + sender + ":" + timestamp + ":" + additional1 + ":" + additional2 + ":" + public_key_hex + ":" + data
		tx_hash = sha256(final.rstrip()).hexdigest()
		signature = messages.sign_message(private_key_hex, tx_hash)
		payload = "TREEPAY" + "," + account + "," + sender + "," + timestamp + "," + additional1 + "," + additional2 + "," + public_key_hex + "," + data + "," + tx_hash + "," + signature.encode("hex")
		cur.execute('SELECT * FROM requests WHERE unique_id=?', (unique_id,))
		result = cur.fetchall()
		if len(result) == 0:
			time_generated = str(int(time.time()))
			if payment_type == "PURCHASE":
				cur.execute('INSERT INTO requests (type,identifier,ticker,time_generated,unique_id,transaction_id,transaction_id_times) VALUES (?,?,?,?,?,?,?)', (payment_type,sender,address_type,time_generated,unique_id,product_hash,times))
				con.commit()
				cur.execute('INSERT INTO messages (type,sender,times,refers_to,unique_id,time_generated) VALUES (?,?,?,?,?,?)', (payment_type,sender,times,product_hash,unique_id,time_generated))
				con.commit()
			else:
				cur.execute('INSERT INTO requests (type,identifier,ticker,time_generated,unique_id,transaction_id,transaction_id_times) VALUES (?,?,?,?,?,?,?)', (payment_type,sender,address_type,time_generated,unique_id,"None","None"))
				con.commit()
				cur.execute('INSERT INTO messages (type,sender,times,refers_to,unique_id,time_generated) VALUES (?,?,?,?,?,?)', (payment_type,sender,"None","None",unique_id,time_generated))
				con.commit()
		else:
			return False
		return payload
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass

def ask_payment(payment_type,product_hash,times,address_type,sender,unique_id):
	try:
		payload = create_payload(payment_type,product_hash,times,address_type,sender,unique_id)
		if sender in payload:
			return_data = requests.post("http://127.0.0.1:10000/data/pool/new", data=payload)
			return True
		else:
			return payload
	except:
		return "Something went wrong!"
	finally:
		try:
			con.close()
		except:
			pass
