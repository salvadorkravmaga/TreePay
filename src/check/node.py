from src.cryptography import encrypt, decrypt, address, messages
from src.payments import getbtcaddress, getltcaddress, price
from src.check import operations, reply, OK, encrypt_reply
from hashlib import sha256
import time
import sqlite3 as sql

def tree_pay(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
	except:
		pass
	try:
		if additional1 == "ASK":
			if len(additional2) != 64:
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
				data = decrypt.decryptWithRSAKey(EncryptionKey,data)
				if data == False:
					return
				data_details = data.split(",")
				payment_type = data_details[0]
				if payment_type == "PURCHASE":
					product_hash = data_details[1]
					cur.execute('SELECT * FROM items WHERE transaction_id=?', (product_hash,))
					result = cur.fetchall()
					if len(result) == 1:
						Price = result[0]["price"]
					else:
						return
					quantity = data_details[2]
					try:
						quantity = int(quantity)
						if quantity < 1:
							return
					except:
						return
					total = float(Price) * quantity
				address_type = data_details[-1]
				if address_type == "BTC":
					try:
						address = getbtcaddress.get_address()
					except:
						OK.send_OK(sender)
						return
					if payment_type == "PURCHASE":
						amount = price.get_price("BTC",total)
						if amount != False:
							reply.send_reply(sender,payment_type,address_type,address,amount,additional2,product_hash,quantity)
					else:
						product_hash = "Donation"
						quantity = "Donation"
						reply.send_reply(sender,payment_type,address_type,address,"0",additional2,product_hash,quantity)
					OK.send_OK(sender)
					return True
				elif address_type == "LTC":
					try:
						address = getltcaddress.get_address()
					except:
						OK.send_OK(sender)
						return
					if payment_type == "PURCHASE":
						amount = price.get_price("LTC",total)
						if amount != False:
							reply.send_reply(sender,payment_type,address_type,address,amount,additional2,product_hash,quantity)
					else:
						product_hash = "Donation"
						quantity = "Donation"
						reply.send_reply(sender,payment_type,address_type,address,"0",additional2,product_hash,quantity)
					OK.send_OK(sender)
					return True
				else:
					return
			else:
				return
		elif additional1 == "REPLY":
			if len(additional2) != 64:
				return
			cur.execute('SELECT * FROM requests WHERE unique_id=? AND identifier=?', (additional2,sender))
			result = cur.fetchall()
			if len(result) != 1:
				return
			payment_type = result[0]["type"]
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
				data = decrypt.decryptWithRSAKey(EncryptionKey,data)
				if data == False:
					return
				data_details = data.split(",")
				if len(data_details) != 3:
					return
				address = data_details[0]
				if payment_type == "DONATE":
					amount = data_details[1]
					if amount != "0":
						return
				else:
					try:
						amount = data_details[1]
						amount = float(amount)
						amount = "%.8f" % amount
						if float(amount) <= 0:
							return
					except:
						return
				transaction_on_success = data_details[2]
				if len(transaction_on_success) != 64:
					return
				time_generated = str(int(time.time()))
				if payment_type != "DONATE":
					cur.execute('UPDATE requests SET address=?,amount=?,time_generated=?,transaction_on_success=? WHERE unique_id=?', (address,amount,time_generated,transaction_on_success,additional2))
					con.commit()
				else:
					cur.execute('UPDATE requests SET address=?,amount=?,time_generated=?,transaction_on_success=? WHERE unique_id=?', (address,"You can donate any amount of money!",time_generated,transaction_on_success,additional2))
					con.commit()
				cur.execute('UPDATE messages SET address=?,transaction_on_success=? WHERE unique_id=?',(address,transaction_on_success,additional2))
				con.commit()
				OK.send_OK(sender)
				return True
			else:
				return
		elif additional1 == "ENCRYPT":
			if additional2 != "None":
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 0:
				EncryptionKey = decrypt.decryptfromPubKey(data)
				if EncryptionKey == False:
					return
				try:
					testEncryptionKey = EncryptionKey.decode("hex")
				except:
					return
				result = encrypt.encryptWithRSAKey(EncryptionKey,"test")
				if result == False:
					return
				test_result = decrypt.decryptWithRSAKey(EncryptionKey,result)
				if test_result == False:
					return
				if test_result != "test":
					return
				time_created = str(int(time.time()))
				cur.execute('INSERT INTO users (identifier,EncryptionKey,NewEncryptionKey,time_generated,encryption) VALUES (?,?,?,?,?)', (sender,EncryptionKey,EncryptionKey,time_created,"INCOMING"))
				con.commit()
				result = encryption_reply.send_reply(sender,EncryptionKey)
				if result == True:
					return True
			elif len(result) == 1:
				time_generated = result[0]["time_generated"]
				encryption_type = result[0]["encryption"]
				if encryption_type == "INCOMING":
					if time.time() - float(time_generated) > 600:
						EncryptionKey = decrypt.decryptfromPubKey(data)
						if EncryptionKey == False:
							return
						try:
							testEncryptionKey = EncryptionKey.decode("hex")
						except:
							return
						Result = encrypt.encryptWithRSAKey(EncryptionKey,"test")
						if Result == False:
							return
						test_result = decrypt.decryptWithRSAKey(EncryptionKey,Result)
						if test_result == False:
							return
						if test_result != "test":
							return
						oldEncryptionKey = result[0]["EncryptionKey"]
						time_created = str(int(time.time()))
						cur.execute('UPDATE users SET EncryptionKey=?,NewEncryptionKey=?,time_generated=? WHERE identifier=?', (EncryptionKey,oldEncryptionKey,time_created,sender))
						con.commit()
						result = encryption_reply.send_reply(sender,EncryptionKey)
						if result == True:
							return True
			else:
				return
		elif additional1 == "ENCRYPT-REPLY":
			if additional2 != "None":
				return
			cur.execute('SELECT * FROM users WHERE identifier=?', (sender,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["NewEncryptionKey"]
				encryption = result[0]["encryption"]
			else:
				return
			if encryption != "OUTGOING":
				return
			data = decrypt.decryptWithRSAKey(EncryptionKey,data)
			if data == False:
				return
			if data == EncryptionKey:
				cur.execute('UPDATE users SET EncryptionKey=? WHERE identifier=?', (data,sender))
				con.commit()
				OK.send_OK(sender)
		elif additional1 == "MESSAGE":
			if len(additional2) != 64:
				return
			cur.execute('SELECT * FROM messages WHERE sender=? AND transaction_on_success=? AND message!=?', (sender,additional2,"None"))
			result = cur.fetchall()
			if len(result) == 1:
				data = decrypt.decryptWithRSAKey(EncryptionKey,data)
				if data == False:
					return
				cur.execute('UPDATE messages SET message=? WHERE sender=? AND transaction_on_success=?', (data,sender,additional2))
				con.commit()
				OK.send_OK(sender)
				return True
			else:
				return
		elif additional1 == "OK":
			requests.get("http://127.0.0.1:10000/received/"+sender+"/OK")
			return True
		else:
			return
	except:
		return
	finally:
		try:
			con.close()
		except:
			pass

def constructor(payload):
	details = payload.split(",")
	operation = details[0]
	sender = details[1]
	receiver = details[2]
	timestamp = details[3]
	additional1 = details[4]
	additional2 = details[5]
        additional3 = details[6]
	data = details[7]
	tx_hash = details[8]
	signature = details[9]
	result = tree_pay(sender,receiver,timestamp,additional1,additional2,additional3,data,tx_hash,signature)
	return result
