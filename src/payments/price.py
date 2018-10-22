import requests
import json
import sqlite3 as sql

def get_price(ticker,amount):
	try:
		con = sql.connect("info.db")
		con.row_factory = sql.Row
		cur = con.cursor()
		cur.execute('SELECT * FROM prices')
		result = cur.fetchall()
		if len(result) != 1:
			return False
		if ticker == "BTC":
			price = result[0]["btc_price"]
		elif ticker == "LTC":
			price = result[0]["ltc_price"]
		else:
			return False
		total = float(amount)/float(price)
		total = "%.8f" % total
		return total
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass
