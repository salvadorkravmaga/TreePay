import requests
import json
import sqlite3 as sql

def get_prices():
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		tries = 0
		while tries < 3:
			try:
				return_data = requests.get("https://api.coinmarketcap.com/v2/ticker/1/?convert=USD")
				return_data = json.loads(return_data.content)
				price = return_data["data"]["quotes"]["USD"]["price"]
				btc_price = "%.2f" % price
				break
			except:
				tries += 1

		tries = 0
		while tries < 3:
			try:
				return_data = requests.get("https://api.coinmarketcap.com/v2/ticker/2/?convert=USD")
				return_data = json.loads(return_data.content)
				price = return_data["data"]["quotes"]["USD"]["price"]
				ltc_price = "%.2f" % price
				break
			except:
				tries += 1

		cur.execute('SELECT * FROM prices')
		result = cur.fetchall()
		if len(result) == 0:
			cur.execute('INSERT INTO prices (btc_price,ltc_price) VALUES (?,?)', (btc_price,ltc_price))
			con.commit()
		elif len(result) == 1:
			cur.execute('UPDATE prices SET btc_price=?,ltc_price=?', (btc_price,ltc_price))
			con.commit()
	except:
		pass
	finally:
		try:
			con.close()
		except:
			pass
