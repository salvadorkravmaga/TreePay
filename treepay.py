#!/usr/bin/env python
# -*- coding: utf-8 -*-

from src.payments import getbtcbalance, getltcbalance, getbtctotalbalance, getltctotalbalance, prices
from src.database import db, structure
from src.proof import proof_of_work
from src.cryptography import keys, address, messages, encrypt, decrypt
from src.check import operations, node
from src import identifier, new_data, online_status, other_nodes, user, message, ask, encryption
from flask import Flask, render_template, request, redirect
from hashlib import sha256
import setup
import requests
import ConfigParser
import sys
import os, os.path
import inspect
import time
import sqlite3 as sql
import thread
import ipaddress

accounts = []
nodes = ["::ffff:185.243.113.106","::ffff:185.243.113.108","::ffff:185.243.113.59"]
connections = []
GetFromSettings = {}
PostToSettings = {}
PostTo = []
my_data = []
my_transactions = []
users = {}
users_search = []
last_ok = {}

path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
config = ConfigParser.RawConfigParser()
config.read("treepayc")

app = Flask(__name__, template_folder='templates', static_url_path='')

try:
	print "[!] Checking accounts"
	con = sql.connect("info.db", check_same_thread=False)
	con.row_factory = sql.Row
	cur = con.cursor()
	cur.execute('SELECT * FROM accounts')
	Accounts = cur.fetchall()
	cur.execute('SELECT * FROM fake_account')
	FakeAccounts = cur.fetchall()
except:
	result = setup.config(path)
	if result == False:
		print "Something went wrong with installation. Exiting.."
		sys.exit(1)
	con = sql.connect("info.db", check_same_thread=False)
	con.row_factory = sql.Row
	cur = con.cursor()
	cur.execute('SELECT * FROM accounts')
	Accounts = cur.fetchall()
	cur.execute('SELECT * FROM fake_account')
	FakeAccounts = cur.fetchall()

if len(Accounts) == 0:
	print "	[!] Generating new account"
	private_key_hex,public_key_hex,Accountaddress = address.generate_account()
	try:
		cur.execute('INSERT INTO accounts (identifier,private_key_hex,public_key_hex) VALUES (?,?,?)', (Accountaddress,private_key_hex,public_key_hex))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)

	try:
		priv_key,pub_key = keys.generate()
	except:
		print "		[-] Error generating private/public keys pair. Exiting.."
		sys.exit(1)

	try:
		cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (Accountaddress,pub_key,priv_key,str(time.time())))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)

	print "		[+] New account " + Accountaddress + " created"
	GetFromSettings.update({Accountaddress:"ALL"})
	PostToSettings.update({Accountaddress:"ALL"})
	accounts.append(Accountaddress)
else:
	if len(Accounts) >= 2:
		print "	[-] You must only use one account! Exiting.."
		sys.exit(1)
	for Account in Accounts:
		try:
			account = Account["identifier"]
			private_key_hex = Account["private_key_hex"]
			public_key_hex = Account["public_key_hex"]
			Accountaddress = address.keyToAddr(public_key_hex,account)
			if Accountaddress != account:
				cur.execute('UPDATE accounts SET identifier=? WHERE identifier=?', (Accountaddress,account))
				con.commit()
			signature = messages.sign_message(private_key_hex,"test")
			if signature == False:
				print "	[-] There was a problem with signature. Exiting.."
				sys.exit(1)
			prove_ownership = messages.verify_message(public_key_hex, signature.encode("hex"), "test")
			if prove_ownership == False:
				print "	[-] The private key " + private_key_hex + " does not prove ownership of " + account
				cur.execute('DELETE FROM accounts WHERE identifier=?', (account,))
				con.commit()
			else:
				print "	[+] Account successfully loaded: " + account
				accounts.append(account)
		except:
			print "	[-] Error with private key. Maybe wrong format (WIF)? Exiting.."
			sys.exit(1)

if len(FakeAccounts) == 0:
	print "	[!] Generating new fake account"
	fake_private_key_hex,fake_public_key_hex,fakeAccountaddress = address.generate_fakeIdentifier()
	try:
		cur.execute('INSERT INTO fake_account (fakeidentifier,fake_private_key_hex,fake_public_key_hex) VALUES (?,?,?)', (fakeAccountaddress,fake_private_key_hex,fake_public_key_hex))
		con.commit()
	except:
		print "		[-] DB error. Exiting.."
		sys.exit(1)
	print "		[+] New fake account " + fakeAccountaddress + " created"
elif len(FakeAccounts) == 1:
	try:
		fake_account = FakeAccounts[0]["fakeidentifier"]
		fake_private_key_hex = FakeAccounts[0]["fake_private_key_hex"]
		fake_public_key_hex = FakeAccounts[0]["fake_public_key_hex"]
		fake_Accountaddress = address.keyToAddr2(fake_public_key_hex,fake_account)
		if fake_Accountaddress != fake_account:
			cur.execute('UPDATE fake_account SET identifier=? WHERE identifier=?', (fake_Accountaddress,fake_account))
			con.commit()
		signature = messages.sign_message(fake_private_key_hex,"test")
		if signature == False:
			print "	[-] There was a problem with signature. Exiting.."
			sys.exit(1)
		prove_ownership = messages.verify_message(fake_public_key_hex, signature.encode("hex"), "test")
		if prove_ownership == False:
			print "	[-] The private key " + fake_private_key_hex + " does not prove ownership of " + fake_account
			cur.execute('DELETE FROM fake_account WHERE identifier=?', (fake_account,))
			con.commit()
		else:
			print "	[+] Fake account successfully loaded: " + fake_account
	except:
		print "	[-] Error with private key. Maybe wrong format (WIF)? Exiting.."
		sys.exit(1)
else:
	print "	[-] More than one fake account detected. Exiting.."
	sys.exit(1)

for account in accounts:
	try:
		post_to_setting = config.get(account, 'PostTo')
		post_to_setting = post_to_setting.replace(" ","")
		PostToSettings.update({account:post_to_setting})
	except:
		PostToSettings.update({account:"ALL"})

	try:
		get_from_setting = config.get(account, 'GetFrom')
		get_from_setting = get_from_setting.replace(" ","")
		GetFromSettings.update({account:get_from_setting})
	except:
		GetFromSettings.update({account:"ALL"})

def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

def memory_new(identifier,payload):
	result = operations.check_payload(payload)
	result_details = result.split(",")
	account = result_details[0]
	result = result_details[1]
	if result == "True":
		if account != identifier:
			return
		try:			
			result = node.constructor(payload)
			return result
		except Exception as e:
			print e
			return "Error"
	else:
		return "None"

def ask_memory(account,peer):
	try:
		original_account = account
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
		result = cur.fetchall()
		if len(result) == 1:
			user = result[0]["identifier"]
			cur.execute('SELECT * FROM fakeAccounts WHERE identifier=?', (user,))
			result = cur.fetchall()
			if len(result) == 1:
				EncryptionKey = result[0]["EncryptionKey"]
			else:
				return
		else:
			return
		cur.execute('SELECT * FROM fake_account')
		accounts = cur.fetchall()
		Account = accounts[0]["fakeidentifier"]
		fake_private_key_hex = accounts[0]["fake_private_key_hex"]
		fake_public_key_hex = accounts[0]["fake_public_key_hex"]
		fake_Address = address.keyToAddr2(fake_public_key_hex, Account)
		timestamp = str(int(time.time()))
		signature = messages.sign_message(fake_private_key_hex, fake_Address+":"+timestamp)
		fake_signature = signature.encode("hex")
		cur.execute('SELECT * FROM accounts WHERE identifier=?', (account,))
		accounts = cur.fetchall()
		private_key_hex = accounts[0]["private_key_hex"]
		public_key_hex = accounts[0]["public_key_hex"]
		signature = messages.sign_message(private_key_hex, account+":"+timestamp)
		signature = signature.encode("hex")
		account = encrypt.encryptWithRSAKey(EncryptionKey,account)
		public_key_hex = encrypt.encryptWithRSAKey(EncryptionKey,public_key_hex)
		signature = encrypt.encryptWithRSAKey(EncryptionKey,signature)
		if account == False or public_key_hex == False or signature == False:
			return
		ip_result = whatis(peer)
		if ip_result == False:
			return
		if ip_result == "4":
			return_data = requests.get("http://"+peer+":12995/memory/search/"+Account+"/"+fake_public_key_hex+"/"+timestamp+"/"+fake_signature+"/"+account+"/"+public_key_hex+"/"+signature)
		else:
			return_data = requests.get("http://["+peer+"]:12995/memory/search/"+Account+"/"+fake_public_key_hex+"/"+timestamp+"/"+fake_signature+"/"+account+"/"+public_key_hex+"/"+signature)
		if return_data.content != "None" and return_data.status_code == 200:
			payload = decrypt.decryptWithRSAKey(EncryptionKey,return_data.content)
			if payload == False:
				return
			result = memory_new(original_account,payload)
			if result == True:
				print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+original_account+"] <- received data from " + peer
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass

def send_online_status():
	try:
		global accounts
		for account in accounts:
			online_status.online_status(account)
	except (Exception,KeyboardInterrupt):
		pass
				
def get_other_nodes():
	try:
		for connection in connections:
			connection_details = connection.split(",")
			account = connection_details[0]
			peer = connection_details[1]
			other_nodes.get(peer)
	except (Exception,KeyboardInterrupt):
		pass
	
def connected_nodes():
	try:
		con = sql.connect("info.db", check_same_thread=False)
		con.row_factory = sql.Row
		cur = con.cursor()
		for GetFromSetting in GetFromSettings:
			account = GetFromSetting
			setting = GetFromSettings[account]
			if setting == "ALL":
				times_found = 0
				for connection in connections:
					connection_details = connection.split(",")
					Account = connection_details[0]
					if Account == account:
						times_found += 1
				if times_found < 16:
					cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT ' + str(16-times_found))
					peers = cur.fetchall()
					if len(peers) > 0:
						for peer in peers:
							found = False
							Peer = peer["peer"]
							Identifier = peer["identifier"]
							for connection in connections:
								connection_details = connection.split(",")
								ACCOUNT = connection_details[0]
								PEER = connection_details[1]
								if ACCOUNT == account and Peer == PEER:
									found = True
									break
							if found == False and Identifier not in accounts:
								payload = account + "," + Peer
								connections.append(payload)
								print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] <- connected to node: " + Peer
			elif setting != "NONE":
				peers = setting.replace(" ","")
				peers = peers.split(",")
				for peer in peers:
					found = False
					for connection in connections:
						connection_details = connection.split(",")
						ACCOUNT = connection_details[0]
						PEER = connection_details[1]
						if ACCOUNT == account and Peer == PEER:
							found = True
							break
					if found == False:
						cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
						result = cur.fetchall()
						if len(result) == 1:
							payload = account + "," + peer
							connections.append(payload)
							print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] <- connected to node: " + peer
		for PostToSetting in PostToSettings:
			account = PostToSetting
			setting = PostToSettings[account]
			if setting == "ALL":
				times_found = 0
				for connection in PostTo:
					connection_details = connection.split(",")
					Account = connection_details[0]
					if Account == account:
						times_found += 1
				if times_found < 16:
					cur.execute('SELECT * FROM peers ORDER BY RANDOM() LIMIT ' + str(16-times_found))
					peers = cur.fetchall()
					if len(peers) > 0:
						for peer in peers:
							found = False
							Identifier = peer["identifier"]
							Peer = peer["peer"]
							for connection in PostTo:
								connection_details = connection.split(",")
								ACCOUNT = connection_details[0]
								PEER = connection_details[1]
								if ACCOUNT == account and Peer == PEER:
									found = True
									break
							if found == False and Identifier not in accounts:
								payload = account + "," + Peer
								PostTo.append(payload)
								print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] -> connected to node: " + Peer
			elif setting != "NONE":
				peers = setting.replace(" ","")
				peers = peers.split(",")
				for peer in peers:
					found = False
					for connection in PostTo:
						connection_details = connection.split(",")
						ACCOUNT = connection_details[0]
						PEER = connection_details[1]
						if ACCOUNT == account and Peer == PEER:
							found = True
							break
					if found == False:
						cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
						result = cur.fetchall()
						if len(result) == 1:
							payload = account + "," + peer
							PostTo.append(payload)
							print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] -> connected to node: " + peer
	except (Exception,KeyboardInterrupt):
		pass
	finally:
		try:
			con.close()
		except:
			pass
	
def ask_for_new_data():
	try:
		for connection in connections:
			connection_details = connection.split(",")
			account = connection_details[0]
			peer = connection_details[1]
			ask_memory(account,peer)
	except (Exception,KeyboardInterrupt):
		pass

def daemon():
	daemon_data_enabled = False
	Last_check = 0
	Last_online = 0
	Last_search = 0
	Last_peers_check = 0
	Last_users_check = 0
	Last_price_check = 0
	while True:

		try:
			con = sql.connect("info.db", check_same_thread=False)
			con.row_factory = sql.Row
			cur = con.cursor()
		except:
			pass

		try:
			cur.execute('SELECT * FROM keys')
			results = cur.fetchall()
			if len(results) > 0:
				checks = 0
				while checks < len(results):
					time_now = time.time()
					timestamp = results[checks]["time_generated"]
					if time_now - float(timestamp) > 900:
						cur.execute('DELETE FROM keys WHERE time_generated=?', (timestamp,))
						con.commit()
					checks += 1
		except:
			pass

		try:
			cur.execute('SELECT * FROM test_peers')
			results = cur.fetchall()
			for result in results:
				peer = result["peer"]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					identifier.get(peer)
				cur.execute('DELETE FROM test_peers WHERE peer=?', (peer,))
				con.commit()
		except:
			pass
		
		if time.time() - Last_peers_check > 300:
			try:
				cur.execute('SELECT * FROM peers')
				results = cur.fetchall()
				for result in results:
					peer = result["peer"]
					identifier.get(peer)
				for node in nodes:
					cur.execute('SELECT * FROM peers WHERE peer=?', (node,))
					result = cur.fetchall()
					if len(result) == 0:
						identifier.get(node)
				Last_peers_check = time.time()
			except:
				pass

		if time.time() - Last_users_check > 60:
			try:
				if len(users_search) > 0:
					for user_search in users_search:
						cur.execute('SELECT * FROM users WHERE identifier=?', (user_search,))
						result = cur.fetchall()
						if len(result) == 0:
							for connection in connections:
								connection_details = connection.split(",")
								peer = connection_details[1]
								userDetails = user.get(peer,user_search)
								if userDetails != False:
									CHECK = online_status.check_payload(userDetails)
									check_details = CHECK.split(",")
									result = check_details[0]
									pubKey = check_details[1]
									last_online = check_details[2]
									if result == "True":
										payload = user_search + "," + pubKey + "," + last_online
										requests.post("http://127.0.0.1:10000/users/new", data=payload)
										cur.execute('INSERT INTO users (identifier,EncryptionKey,NewEncryptionKey,time_generated,encryption) VALUES (?,?,?,?,?)', (user_search,"0","0","0","OUTGOING"))
										con.commit()
										users_search.remove(user_search)
										break
							Last_users_check = time.time()
						else:
							users_search.remove(user_search)
			except:
				pass

		try:
			cur.execute('SELECT * FROM users WHERE encryption=?', ("OUTGOING",))
			results = cur.fetchall()
			for result in results:
				User = result["identifier"]
				time_generated = result["time_generated"]
				EncryptionKey = result["EncryptionKey"]
				if time.time() - float(time_generated) > 650 or EncryptionKey == "0":
					found = False
					for connection in connections:
						connection_details = connection.split(",")
						peer = connection_details[1]
						userDetails = user.get(peer,User)
						if userDetails != False:
							CHECK = online_status.check_payload(userDetails)
							check_details = CHECK.split(",")
							result = check_details[0]
							pubKey = check_details[1]
							last_online = check_details[2]
							if result == "True":
								payload = User + "," + pubKey + "," + last_online
								requests.post("http://127.0.0.1:10000/users/new", data=payload)
								found = True
								break
					if found == True:
						EncryptionKey = os.urandom(32)
						EncryptionKey = EncryptionKey.encode("hex")
						result = encryption.get_encryption(User,EncryptionKey)
						if result == True:
							time_generated = int(time.time())
							cur.execute('UPDATE users SET EncryptionKey=?,NewEncryptionKey=?,time_generated=? WHERE identifier=?', ("1",EncryptionKey,time_generated,User))
							con.commit()
		except:
			pass

		try:
			cur.execute('SELECT * FROM requests WHERE address=?', ("None",))
			results = cur.fetchall()
			for result in results:
				time_generated = result["time_generated"]
				if time.time() - float(time_generated) > 720:
					unique_id = result["unique_id"]
					cur.execute('DELETE FROM requests WHERE unique_id=?', (unique_id,))
					con.commit()
					cur.execute('DELETE FROM messages WHERE unique_id=?', (unique_id,))
					con.commit()
		except:
			pass

		try:
			cur.execute('SELECT * FROM requests WHERE address!=? AND type=?', ("None","PURCHASE"))
			results = cur.fetchall()
			for result in results:
				time_generated = result["time_generated"]
				if time.time() - float(time_generated) > 600:
					unique_id = result["unique_id"]
					cur.execute('DELETE FROM requests WHERE unique_id=?', (unique_id,))
					con.commit()
					cur.execute('DELETE FROM messages WHERE unique_id=?', (unique_id,))
					con.commit()
		except:
			pass

		try:
			cur.execute('SELECT * FROM automated_response')
			responses = cur.fetchall()
			if len(responses) == 1:
				purchase_response = responses[0]["purchase_response"]
				donation_response = responses[0]["donation_response"]
				cur.execute('SELECT * FROM addresses WHERE address=? AND paid=?', (address,'None'))
				results = cur.fetchall()
				for result in results:
					payment_type = result["type"]
					sender = result["identifier"]
					ticker = result["ticker"]
					address = result["address"]
					amount = result["amount"]
					if ticker == "BTC":
						try:
							balance = getbtcbalance.get_balance(address)
							if str(balance) == amount:
								transaction_on_success = result["transaction_on_success"]
								if payment_type == "PURCHASE":
									sent = message.new_message(sender,transaction_on_success,purchase_response)
									if sent == True:
										cur.execute('UPDATE addresses SET paid=? WHERE transaction_on_success=?', ("Paid",transaction_on_success))
										con.commit()
								elif payment_type == "DONATE":
									sent = message.new_message(sender,transaction_on_success,donation_response)
									if sent == True:
										cur.execute('UPDATE addresses SET paid=? WHERE transaction_on_success=?', ("Paid",transaction_on_success))
										con.commit()
						except:
							pass
					elif ticker == "LTC":
						try:
							balance = getltcbalance.get_balance(address)
							if str(balance) == amount:
								transaction_on_success = result["transaction_on_success"]
								if payment_type == "PURCHASE":
									sent = message.new_message(sender,transaction_on_success,purchase_response)
									if sent == True:
										cur.execute('UPDATE addresses SET paid=? WHERE transaction_on_success=?', ("Paid",transaction_on_success))
										con.commit()
								elif payment_type == "DONATE":
									sent = message.new_message(sender,transaction_on_success,donation_response)
									if sent == True:
										cur.execute('UPDATE addresses SET paid=? WHERE transaction_on_success=?', ("Paid",transaction_on_success))
										con.commit()
						except:
							pass
		except:
			pass

		try:
			cur.execute('SELECT * FROM addresses WHERE paid=?', ("None",))
			results = cur.fetchall()
			for result in results:
				transaction_on_success = result["transaction_on_success"]
				time_generated = result["time_generated"]
				if time.time() - float(time_generated) > 600:
					cur.execute('DELETE FROM addresses WHERE transaction_on_success=?', (transaction_on_success,))
					con.commit()
					cur.execute('DELETE FROM messages WHERE transaction_on_success=?', (transaction_on_success,))
					con.commit()
		except:
			pass

		try:
			for connection in connections:
				connection_details = connection.split(",")
				account = connection_details[0]
				peer = connection_details[1]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					connections.remove(connection)
					print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] X disconnected from node: " + peer
			for connection in PostTo:
				connection_details = connection.split(",")
				account = connection_details[0]
				peer = connection_details[1]
				cur.execute('SELECT * FROM peers WHERE peer=?', (peer,))
				result = cur.fetchall()
				if len(result) == 0:
					PostTo.remove(connection)
					print time.strftime("%d/%m/%Y %H:%M:%S", time.gmtime()) + " ["+account+"] X disconnected from node: " + peer
		except:
			pass
		
		try:
			for account in accounts:
				cur.execute('SELECT * FROM keys WHERE identifier=? ORDER BY time_generated DESC LIMIT 1', (account,))
				results = cur.fetchall()
				if len(results) > 0:
					last_generated = results[0]["time_generated"]
					if time.time() - float(last_generated) >= 300:
						priv_key,pub_key = keys.generate()
						time_now = time.time()
						cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (account,pub_key,priv_key,str(time_now)))
						con.commit()
				else:
					priv_key,pub_key = keys.generate()
					time_now = time.time()
					cur.execute('INSERT INTO keys (identifier,public_key,private_key,time_generated) VALUES (?,?,?,?)', (account,pub_key,priv_key,str(time_now)))
					con.commit()
		except:
			pass

		try:
			if len(my_data) > 0:
				peers_to_post = []
				for connection in PostTo:
					connection_details = connection.split(",")
					peer = connection_details[1]
					if peer not in peers_to_post:
						peers_to_post.append(peer)
				for data_to_post in my_data:
					if len(PostTo) > 0:
						data_to_post_details = data_to_post.split(",")
						receiver = data_to_post_details[2]
						if receiver in accounts:
							for peer in peers_to_post:
								new_data.new_data(peer,data_to_post)
							my_data.remove(data_to_post)
						else:
							return_data = requests.get("http://127.0.0.1:10000/sent/"+receiver)
							try:
								times = return_data.content
								if int(times) - 1 <= 10:
									for peer in peers_to_post:
										new_data.new_data(peer,data_to_post)
									my_data.remove(data_to_post)
							except:
								pass
		except:
			pass

		try:
			for transaction in my_transactions:
				details = transaction.split(",")
				timestamp = details[1]
				if time.time() - float(timestamp) > 2000:
					my_transactions.remove(transaction)
		except:
			pass

		if time.time() - Last_price_check > 120:
			try:
				prices.get_prices()
			except:
				pass

		if time.time() - Last_check > 60:
			connected_nodes()
			get_other_nodes()
			Last_check = time.time()
		if time.time() - Last_online > 300:
			send_online_status()
			Last_online = time.time()
		if time.time() - Last_search > 2:
			ask_for_new_data()
			Last_search = time.time()

		try:
			con.close()
		except:
			pass

@app.route('/sent/<receiver>', methods=['GET'])
def sent(receiver):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for USER in last_ok:
			if USER == receiver:
				found = True
				break
		if found == True:
			last_ok[receiver] = last_ok[receiver] + 1
		else:
			last_ok.update({receiver:1})
		return str(last_ok[receiver])
	else:
		abort(403)

@app.route('/received/<sender>/OK', methods=['GET'])
def received_OK(sender):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for USER in last_ok:
			if USER == sender:
				found = True
				break
		if found == True:
			last_ok[sender] = 0
		else:
			last_ok.update({sender:0})
		return "Done"
	else:
		abort(403)
 
@app.route("/")
def redirect_to_index():
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route('/tx/new', methods=['POST'])
def my_transactions_add():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		found = False
		for my_transaction in my_transactions:
			my_transaction_details = my_transaction.split(",")
			tx_hash = my_transaction_details[0]
			if data == tx_hash:
				found = True
				break
		if found == False:
			my_transactions.append(data+","+str(int(time.time())))
		return "Done"
	else:
		abort(403)

@app.route('/tx/<tx>', methods=['GET'])
def check_transaction(tx):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		for transaction in my_transactions:
			details = transaction.split(",")
			tx_hash = details[0]
			if tx_hash == tx:
				found = True
				break
		return str(found)
	else:
		abort(403)

@app.route('/data/pool/new', methods=['POST'])
def data_pool_new():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		if data not in my_data:
			my_data.append(data)
		return "Done"
	else:
		abort(403)

@app.route('/user/<User>', methods=['GET'])
def check_user(User):
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		found = False
		try:
			public_key = users[User]
			return public_key
		except:
			return "None"
	else:
		abort(403)

@app.route('/users/new', methods=['POST'])
def users_add():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		data_details = data.split(",")
		user = data_details[0]
		public_key = data_details[1]
		found = False
		for USER in users:
			if USER == user:
				found = True
				break
		if found == True:
			users[user] = public_key
		else:
			users.update({user:public_key})
		return "Done"
	else:
		abort(403)

@app.route('/user/search', methods=['POST'])
def user_search():
	if request.remote_addr == "127.0.0.1" or request.remote_addr == "::ffff:127.0.0.1":
		data = request.data
		if len(data) < 36 or len(data) > 50:
			return "False"
		else:
			if data not in users_search:
				users_search.append(data)
		return "Done"
	else:
		abort(403)

@app.route("/automated", methods=["POST"])
def add_automated():
	response = request.form['response']
	if response == "":
		result = "You need to add a response"
		return render_template("result.html", result=result)
	donation_response = request.form['donation_response']
	if donation_response == "":
		result = "You need to add a donation response"
		return render_template("result.html", result=result)
	cur.execute('SELECT * FROM automated_response')
	result = cur.fetchall()
	if len(result) == 0:
		cur.execute('INSERT INTO automated_response (purchase_response,donation_response) VALUES (?,?)', (response,donation_response))
		con.commit()
	else:
		cur.execute('UPDATE automated_response SET purchase_response=?, donation_response=?', (response,donation_response))
		con.commit()
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route("/request/<Transaction_id>", methods=["GET"])
def request_view(Transaction_id):
	cur.execute('SELECT * FROM requests WHERE transaction_on_success=?', (Transaction_id,))
	result = cur.fetchall()
	if len(result) == 1:
		payment_type = result[0]["type"]
		if payment_type == "PURCHASE":
			ticker = result[0]["ticker"]
			address = result[0]["address"]
			amount = result[0]["amount"]
			transaction_id = result[0]["transaction_id"]
			transaction_id_times = result[0]["transaction_id_times"]
			time_generated = result[0]["time_generated"]
			payout_time = int(float(time_generated)) + 600
			payout_time = time.ctime(int(payout_time))
			return render_template("request.html",payment_type=payment_type,ticker=ticker,address=address,amount=amount,transaction_id=transaction_id,transaction_id_times=transaction_id_times,payout_time=payout_time)
		else:
			ticker = result[0]["ticker"]
			address = result[0]["address"]
			return render_template("request.html",payment_type=payment_type,ticker=ticker,address=address)
	else:
		return redirect("http://127.0.0.1:10000/", code=302)

@app.route("/message/<Transaction_id>", methods=["GET","POST"])
def message_new(Transaction_id):
	if request.method == "GET":
		cur.execute('SELECT * FROM messages WHERE transaction_on_success=?', (Transaction_id,))
		result = cur.fetchall()
		if len(result) == 1:
			sender = result[0]["sender"]
			transaction_on_success = result[0]["transaction_on_success"]
			message = result[0]["message"]
			return render_template("message.html",sender=sender,transaction_on_success=transaction_on_success,message=message)
		else:
			return redirect("http://127.0.0.1:10000/", code=302)
	elif request.method == "POST":
		sender = request.form['sender']
		if sender == "" or len(sender) < 36 or len(sender) > 50:
			result = "You need to add a sender"
			return render_template("result.html", result=result)
		transaction_on_success = request.form['transaction_on_success']
		if transaction_on_success == "" or len(transaction_on_success) != 64:
			result = "You need to add a valid transaction on success"
			return render_template("result.html", result=result)
		message = request.form['message']
		if message == "":
			result = "You need to type a message"
			return render_template("result.html", result=result)
		result = message.new_message(sender,transaction_on_success,message)
		if result == True:
			return render_template("success.html")
		else:
			return render_template("result.html", result=result)
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route("/item", methods=["POST"])
def add_item():
	title = request.form['title']
	if title == "":
		result = "You need to add a title"
		return render_template("result.html", result=result)
	try:
		price = request.form['price']
		price = float(price)
	except:
		result = "You need to add a valid price"
		return render_template("result.html", result=result)
	final = str(title) + ":" + str(price)
	transaction_id = sha256(final.rstrip()).hexdigest()
	cur.execute('SELECT * FROM items WHERE transaction_id=?', (transaction_id,))
	result = cur.fetchall()
	if len(result) == 0:
		cur.execute('INSERT INTO items (title,price,transaction_id) VALUES (?,?,?)', (title,price,transaction_id))
		con.commit()
	else:
		result = "Another item with this transaction id already exists"
		return render_template("result.html", result=result)
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route("/item/<Transaction_id>/update", methods=["GET","POST"])
def update_item(Transaction_id):
	if request.method == "GET":
		cur.execute('SELECT * FROM items WHERE transaction_id=?', (Transaction_id,))
		result = cur.fetchall()
		if len(result) == 1:
			title = result[0]["title"]
			price = result[0]["price"]
			return render_template("item.html",title=title,price=price)
		else:
			return redirect("http://127.0.0.1:10000/", code=302)
	elif request.method == "POST":
		title = request.form['title']
		if title == "":
			result = "You need to add a title"
			return render_template("result.html", result=result)
		try:
			price = request.form['price']
			price = float(price)
		except:
			result = "You need to add a valid price"
			return render_template("result.html", result=result)
		final = str(title) + ":" + str(price)
		transaction_id = sha256(final.rstrip()).hexdigest()
		cur.execute('SELECT * FROM items WHERE transaction_id=?', (transaction_id,))
		result = cur.fetchall()
		if len(result) == 0:
			cur.execute('INSERT INTO items (title,price,transaction_id) VALUES (?,?,?)', (title,price,transaction_id))
			con.commit()
			cur.execute('DELETE FROM items WHERE transaction_id=?', (Transaction_id,))
			con.commit()
		else:
			result = "Another item with this transaction id already exists"
			return render_template("result.html", result=result)
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route("/item/<transaction_id>/delete", methods=["GET"])
def delete_item(transaction_id):
	if len(transaction_id) != 64:
		result = "Invalid transaction id"
		return render_template("result.html", result=result)
	cur.execute('SELECT * FROM items WHERE transaction_id=?', (transaction_id,))
	result = cur.fetchall()
	if len(result) == 0:
		result = "This item doesn't exist"
		return render_template("result.html", result=result)
	else:
		cur.execute('DELETE FROM items WHERE transaction_id=?', (transaction_id,))
		con.commit()
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route("/message/<transaction_id>/delete", methods=["GET"])
def delete_message(transaction_id):
	if len(transaction_id) != 64:
		result = "Invalid transaction id"
		return render_template("result.html", result=result)
	cur.execute('SELECT * FROM messages WHERE transaction_on_success=?', (transaction_id,))
	result = cur.fetchall()
	if len(result) == 0:
		result = "This message doesn't exist"
		return render_template("result.html", result=result)
	else:
		cur.execute('DELETE FROM messages WHERE transaction_id=?', (transaction_id,))
		con.commit()
	return redirect("http://127.0.0.1:10000/btc", code=302)

@app.route("/btc")
def bitcoin():
	try:
		balance = getbtctotalbalance.get_balance()
	except:
		balance = "Bitcoind is not running!"
	if str(balance) == "0E-8":
		balance = "0.00000000"
	ticker = "BTC"
	url = request.base_url
	user = accounts[0]
	cur.execute('SELECT * FROM requests WHERE ticker=?', (ticker,))
	requests = cur.fetchall()
	cur.execute('SELECT * FROM addresses WHERE ticker=?', (ticker,))
	addresses = cur.fetchall()
	Addresses = []
	for Address in addresses:
		ADDRESS = Address["address"]
		AMOUNT = Address["amount"]
		balance = getbtcbalance.get_balance(ADDRESS)
		if str(balance) != "0E-8":
			Addresses.append(Address)
	cur.execute('SELECT * FROM items')
	items = cur.fetchall()
	cur.execute('SELECT * FROM automated_response')
	automated_response = cur.fetchall()
	try:
		response = automated_response[0]["purchase_response"]
		donation_response = automated_response[0]["donation_response"]
	except:
		response = ""
		donation_response = ""
	cur.execute('SELECT * FROM messages WHERE transaction_on_success!=? AND message!=?', ('None','None'))
	messages = cur.fetchall()
	return render_template('index.html',url=url,user=user,balance=balance,ticker=ticker,requests=requests,addresses=Addresses,items=items,response=response,donation_response=donation_response,messages=messages,requests_count=len(requests),items_count=len(items),messages_count=len(messages))

@app.route("/ltc")
def litecoin():
	try:
		balance = getltctotalbalance.get_balance()
	except:
		balance = "Litecoind is not running!"
	if str(balance) == "0E-8":
		balance = "0.00000000"
	ticker = "LTC"
	url = request.base_url
	user = accounts[0]
	cur.execute('SELECT * FROM requests WHERE ticker=?', (ticker,))
	requests = cur.fetchall()
	cur.execute('SELECT * FROM addresses WHERE ticker=?', (ticker,))
	addresses = cur.fetchall()
	Addresses = []
	for Address in addresses:
		ADDRESS = Address["address"]
		AMOUNT = Address["amount"]
		Balance = getltcbalance.get_balance(ADDRESS)
		if str(Balance) != "0E-8":
			Addresses.append(Address)
	cur.execute('SELECT * FROM items')
	items = cur.fetchall()
	cur.execute('SELECT * FROM automated_response')
	automated_response = cur.fetchall()
	try:
		response = automated_response[0]["purchase_response"]
		donation_response = automated_response[0]["donation_response"]
	except:
		response = ""
		donation_response = ""
	cur.execute('SELECT * FROM messages WHERE transaction_on_success!=? AND message!=?', ('None','None'))
	messages = cur.fetchall()
	return render_template('index.html',url=url,user=user,balance=balance,ticker=ticker,requests=requests,addresses=Addresses,items=items,response=response,donation_response=donation_response,messages=messages,requests_count=len(requests),items_count=len(items),messages_count=len(messages))

@app.route("/<ticker>/donate", methods=["POST"])
def make_donation(ticker):
	recipient = request.form['recipient']
	if len(recipient) < 36 or len(recipient) > 50:
		result = "Invalid recipient"
		return render_template("result.html", result=result)
	if ticker == "btc":
		address_type = "BTC"
	elif ticker == "ltc":
		address_type = "LTC"
	else:
		result = "Payment method " + ticker.upper() + " for now is not supported!"
		return render_template("result.html", result=result)
	unique_id = os.urandom(32)
	unique_id = unique_id.encode("hex")
	unique_id = sha256(unique_id.rstrip()).hexdigest()
	payment_type = "DONATE"
	result = ask.ask_payment(payment_type,"0","0",address_type,recipient,unique_id)
	if result == True:
		return render_template("success.html")
	else:
		return render_template("result.html", result=result)

@app.route("/<ticker>/request", methods=["POST"])
def make_request(ticker):
	recipient = request.form['recipient']
	if len(recipient) < 36 or len(recipient) > 50:
		result = "Invalid recipient"
		return render_template("result.html", result=result)
	transaction_id = request.form['tx']
	if len(transaction_id) != 64:
		result = "Invalid transaction ID"
		return render_template("result.html", result=result)
	transaction_id_times = request.form['quantity']
	try:
		transaction_id_times = int(transaction_id_times)
	except:
		result = "Invalid quantity"
		return render_template("result.html", result=result)
	if ticker == "btc":
		address_type = "BTC"
	elif ticker == "ltc":
		address_type = "LTC"
	else:
		result = "Payment method " + ticker.upper() + " for now is not supported!"
		return render_template("result.html", result=result)
	unique_id = os.urandom(32)
	unique_id = unique_id.encode("hex")
	unique_id = sha256(unique_id.rstrip()).hexdigest()
	payment_type = "PURCHASE"
	result = ask.ask_payment(payment_type,transaction_id,transaction_id_times,address_type,recipient,unique_id)
	if result == True:
		return render_template("success.html")
	else:
		return render_template("result.html", result=result)
 
if __name__ == "__main__":
	thread.start_new_thread(daemon,())
	app.run(port=10000)
