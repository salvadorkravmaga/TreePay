import requests
import ipaddress

def whatis(ip):
	try:
		result = ipaddress.ip_address(unicode(ip))
		return str(result.version)
	except:
		return False

def get(peer,user):
	try:
		ip_result = whatis(peer)
		if ip_result == False:
			return
		if ip_result == "4":
			return_data = requests.get("http://"+peer+":12995/user/"+user)
		else:
			return_data = requests.get("http://["+peer+"]:12995/user/"+user)
		if return_data.content != "None" and return_data:
			return return_data.content
		else:
			return False
	except:
		return False
	finally:
		try:
			con.close()
		except:
			pass
