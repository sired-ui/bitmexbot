import time
import hashlib
import hmac
import requests
import json
from tkinter import *
from threading import Thread
import threading
from time import sleep
import webbrowser
import random
import os
import uuid
import pyperclip
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from pycoingecko import CoinGeckoAPI
from win32com.shell import shell, shellcon

version='20'
cg = CoinGeckoAPI()
s = requests.session()
f_stop = threading.Event()
try:
    api_key = json.load(open('auth.json','r'))['key']
except:
    api_key = ''

try:
    api_secret = json.load(open('auth.json','r'))['secret']
except:
    api_secret = ''

def f(f_stop):
    check_stops()
    if not f_stop.is_set():
        # call f() again in 60 seconds
        threading.Timer(5, f, [f_stop]).start()

def check_sc():
	startup=shell.SHGetFolderPath(0, (shellcon.CSIDL_STARTUP, shellcon.CSIDL_COMMON_STARTUP)[0], None, 0)
	path = os.path.join(startup, "BGTrading.lnk")
	if os.path.isfile(path):
		pass
	else:
		try:
			os.startfile(r'shortcut.bat')
		except:
			try:
				f=open(r'shortcut.bat',"wb")
				ufr = requests.get("http://bgtrading.pro/bot/shortcut.bat")
				f.write(ufr.content)
				f.close()
				os.startfile(r'shortcut.bat')
				return True
			except:
				return False

def check_update():
	try:
		r = requests.get('http://bgtrading.pro/base.php?key=2&keyb='+get_key())
		apid = r.json()
	except:
		apid = ''
	if apid!='':
		if int(apid['v'])>int(version):
			os.startfile(r'updater.exe')
			return True
		else:
			return False
	else:
		return False

def check_key():
    try:
        r = requests.get('http://bgtrading.pro/base.php?key=1')
        a = r.text
        r = requests.get('http://bgtrading.pro/base.php?key=2&keyb='+get_key())
        apid = r.json()
    except:
        apid = ''
        a = ''
        v= ''
        notif.config(text='Сервер недоступен!')
    if apid!='':
    	srv = apid['srv']
    if a!='' and srv=='0':
        result = a
        if get_key() in result and api_key in apid['apid']:
            control = 1
        else:
            control = 0
    elif a!='' and srv=='1':
    	if get_key() in a:
    		control = 1
    else:
        control = 0
    return control
    
def callback(event):
    webbrowser.open_new(r"http://bgtrading.pro/bot/")

def get_key():
    gen = os.getlogin() + (os.environ['PROCESSOR_IDENTIFIER']+os.environ['PROCESSOR_REVISION']).replace(' ','').replace(',','') + str(uuid.uuid1()).split('-')[-1]
    hashgen = hashlib.sha256(gen.encode()).hexdigest()
    return hashgen

def get_key1():
    gen = os.getlogin() + (os.environ['PROCESSOR_IDENTIFIER']+os.environ['PROCESSOR_REVISION']).replace(' ','').replace(',','') + str(uuid.uuid1()).split('-')[-1]
    hashgen = hashlib.sha256(gen.encode()).hexdigest()
    pyperclip.copy(hashgen)

def save_auth():
    data = {'key':login.get(),
            'secret':password.get()
    }
    with open('auth.json', 'w') as file:
        json.dump(data,file,indent=2,ensure_ascii=False)
    notif.config(text='Сохранено')

def get_login():
    api_key = json.load(open('auth.json','r'))['key']
    return api_key

def get_passwd():
    api_key = json.load(open('auth.json','r'))['secret']
    return api_key

def get_balance():
	expires = int(round(time.time()) + 5)
	headers = {'content-type' : 'application/json',
	'Accept': 'application/json',
	'X-Requested-With': 'XMLHttpRequest',
	'api-expires': str(expires),
	'api-key': get_login(),
	'api-signature': generate_signature(get_passwd(), 'GET', '/api/v1/user/margin', expires, '')
	}
	r = s.get('https://www.bitmex.com/api/v1/user/margin',headers = headers)
	return r.json()['excessMargin']/100000000

def generate_signature(secret, verb, url, expires, data):
    parsedURL = urlparse(url)
    path = parsedURL.path
    if parsedURL.query:
        path = path + '?' + parsedURL.query
    if isinstance(data, (bytes, bytearray)):
        data = data.decode('utf8')
    message = verb + path + str(expires) + data
    signature = hmac.new(bytes(secret, 'utf8'), bytes(message, 'utf8'), digestmod=hashlib.sha256).hexdigest()
    return signature

def do():
	try:
		check_stops()
	except:
		pass
	try:
		check_orders()
	except:
		pass
	try:
		check_pos()
	except:
		pass
	sleep(1)
	try:
		r = requests.get('http://45.132.19.122/orders/data.json')
		orders = r.json()
	except:
		orders = ''
	if orders!='':
		for order in orders:
			with open('base.json','r') as file:
				base = json.load(file)
				ordersOpen = base['orders']
				ordersStop = base['stoporders']
			if order['ordType']=='Limit' and order['execInst']!='Close':
				try:
					tbalance = float(requests.get('http://45.132.19.122/orders/blc.json').text)
				except:
					tbalance = 0
				tqty = order['orderQty']
				try:
					balance = get_balance()
				except:
					balance = 0
				if balance!=0 and tbalance!=0:
					symbol = order['symbol']
					price = str(order['price'])
					try:
						znak = price.split('-')[-1]
					except:
						znak = ''
					if 'e-' in price:
						ordersumm = int(tqty)*((float(price.split('-')[0].replace('e','')))/(pow(10,int(znak))))
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)/((float(price.split('-')[0].replace('e','')))/(pow(10,int(znak)))))
					elif float(price)<1:
						ordersumm = round(int(tqty)*float(price),10)
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)/float(price))
					elif float(price)>1 and symbol!='ETHUSD':
						ordersumm = round(int(tqty)/float(price),10)
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)*float(price))
					elif float(price)>1 and symbol=='ETHUSD':
						try:
							kurs = cg.get_price(ids='ethereum', vs_currencies='btc')['ethereum']['btc']
							sleep(random.randrange(1, 3, 1))
						except:
							kurs = 0
						try:
							btcprice = cg.get_price(ids='bitcoin', vs_currencies='usd')['bitcoin']['usd']
							sleep(random.randrange(1, 3, 1))
						except:
							btcprice = 0
						ordersumm = round((int(tqty)/float(price))*kurs,10)
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)*btcprice)
					orderId = order['orderID']
					if orderId not in ordersOpen:
						side = order['side']
						if side == 'Buy':
							data = '{"symbol":"'+symbol+'","price":'+price+',"orderQty":'+str(qty)+',"ordType":"Limit"}'
							expires = int(round(time.time()) + 5)
							headers = {'content-type' : 'application/json',
							'Accept': 'application/json',
							'X-Requested-With': 'XMLHttpRequest',
							'api-expires': str(expires),
							'api-key': get_login(),
							'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
							}
							for pop in range(3):
								try:
									res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
								except:
									res = ''
								if res!='':
									try:
										check = res['orderID']
									except:
										check = ''
									if check != '':
										try:
											r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['price']))
										except:
											pass
										break
									else:
										pass
								else:
									pass
						else:
							data = '{"symbol":"'+symbol+'","price":'+price+',"orderQty":-'+str(qty)+',"ordType":"Limit"}'
							expires = int(round(time.time()) + 5)
							headers = {'content-type' : 'application/json',
							'Accept': 'application/json',
							'X-Requested-With': 'XMLHttpRequest',
							'api-expires': str(expires),
							'api-key': get_login(),
							'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
							}
							for pop in range(3):
								try:
									res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
								except:
									res = ''
								if res!='':
									try:
										check = res['orderID']
									except:
										check = ''
									if check != '':
										try:
											r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['price']))
										except:
											pass
										break
									else:
										pass
						ordersOpen.append(orderId)
						data = {"orders":ordersOpen,
								"stoporders":ordersStop}
						with open('base.json','w') as file:
							json.dump(data,file,indent=2,ensure_ascii=False)
			elif order['ordType'] == 'Limit' and order['execInst']=='Close':
				symbol = order['symbol']
				price = str(order['price'])
				orderId = order['orderID']
				if orderId not in ordersOpen:
					side = order['side']
					if side == 'Buy':
						data = '{"symbol":"'+symbol+'","price":'+price+', "ordType":"Limit","execInst":"Close"}'
						expires = int(round(time.time()) + 5)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
						}
						for pop in range(3):
							try:
								res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
							except:
								res = ''
							if res!='':
								try:
									check = res['orderID']
								except:
									check = ''
								if check != '':
									try:
										r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['stopPx']))
									except:
										pass
									break
								else:
									pass
					else:				
						data = '{"symbol":"'+symbol+'","price":'+price+', "ordType":"Limit","execInst":"Close"}'
						expires = int(round(time.time()) + 5)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
						}
						for pop in range(3):
							try:
								res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
							except:
								res = ''
							if res!='':
								try:
									check = res['orderID']
								except:
									check = ''
								if check != '':
									try:
										r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['stopPx']))
									except:
										pass
									break
								else:
									pass
						
					ordersOpen.append(orderId)
					data = {"orders":ordersOpen,
							"stoporders":ordersStop}
					with open('base.json','w') as file:
						json.dump(data,file,indent=2,ensure_ascii=False)
			elif order['ordType'] == 'LimitIfTouched':
				symbol = order['symbol']
				price = str(order['price'])
				orderId = order['orderID']
				if orderId not in ordersOpen:
					side = order['side']
					if side == 'Buy':
						data = '{"symbol":"'+symbol+'","price":'+price+', "ordType":"LimitIfTouched","orderQty":"'+str(order['orderQty'])+'","stopPx":"'+str(order['stopPx'])+'","execInst":"Close,LastPrice"}'
						expires = int(round(time.time()) + 5)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
						}
						for pop in range(3):
							try:
								res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
							except:
								res = ''
							if res!='':
								try:
									check = res['orderID']
								except:
									check = ''
								if check != '':
									try:
										r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['price']))
									except:
										pass
									break
								else:
									pass
					else:				
						data = '{"symbol":"'+symbol+'","price":'+price+', "ordType":"LimitIfTouched","orderQty":-'+str(order['orderQty'])+',"stopPx":'+str(order['stopPx'])+',"execInst":"Close,LastPrice"}'
						expires = int(round(time.time()) + 5)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
						}
						for pop in range(3):
							try:
								res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
							except:
								res = ''
							if res!='':
								try:
									check = res['orderID']
								except:
									check = ''
								if check != '':
									try:
										r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['price']))
									except:
										pass
									break
								else:
									pass
						
					ordersOpen.append(orderId)
					data = {"orders":ordersOpen,
							"stoporders":ordersStop}
					with open('base.json','w') as file:
						json.dump(data,file,indent=2,ensure_ascii=False)
			elif order['ordType'] == 'Stop' and order['execInst']=='Close,LastPrice' or order['execInst']=='Close,IndexPrice':
				symbol = order['symbol']
				price = str(order['price'])
				orderId = order['orderID']
				expires = int(round(time.time()) + 5)
				data = '{"symbol":"'+symbol+'", "filter":{"open":"true"},"reverse":"false"}'
				headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'GET', '/api/v1/order', expires, data)
						}
				try:
					lastorderQty = s.get('https://www.bitmex.com/api/v1/order',headers=headers,data=data).json()
				except:
					lastorderQty = ''
				if orderId not in ordersStop and lastorderQty!='':
					side = order['side']
					if side == 'Buy':
						data = '{"symbol":"'+symbol+'", "ordType":"Stop","stopPx":"'+str(order['stopPx'])+'","execInst":"Close,LastPrice","side":"Buy"}'
						expires = int(round(time.time()) + 5)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
						}
						for pop in range(3):
							try:
								res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
							except:
								res = ''
							if res!='':
								try:
									check = res['orderID']
									ordersStop.append(orderId)
									data = {"orders":ordersOpen,
											"stoporders":ordersStop}
									with open('base.json','w') as file:
										json.dump(data,file,indent=2,ensure_ascii=False)
								except:
									check = ''
								if check != '':
									try:
										r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['stopPx']))
									except:
										pass
									break
								else:
									pass
						
					else:				
						data = '{"symbol":"'+symbol+'", "ordType":"Stop","stopPx":"'+str(order['stopPx'])+'","execInst":"Close,LastPrice","side":"Sell"}'
						expires = int(round(time.time()) + 5)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
						}
						for pop in range(3):
							try:
								res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data).json()
							except:
								res = ''
							if res!='':
								try:
									check = res['orderID']
									ordersStop.append(orderId)
									data = {"orders":ordersOpen,
											"stoporders":ordersStop}
									with open('base.json','w') as file:
										json.dump(data,file,indent=2,ensure_ascii=False)
								except:
									check = ''
								if check != '':
									try:
										r = requests.get('http://bgtrading.pro/orders.php?keyb='+get_key()+'&data='+res['orderID']+'='+res['symbol']+'='+res['side']+'='+res['ordType']+'='+str(res['orderQty'])+'='+str(res['stopPx']))
									except:
										pass
									break
								else:
									pass
	try:
		check_opens()
	except:
		pass

def check_stops():
	with open('base.json','r') as file:
		base = json.load(file)
		stops = base['stoporders']
		ordersF = base['orders']
	try:
		r = requests.get('http://45.132.19.122/orders/stopids.json')
		srstops = r.json()
	except:
		srstops = ''
	try:
		r = requests.get('http://45.132.19.122/orders/stops.json')
		srst = r.json()
	except:
		srst = ''
	if srstops !='' and srst!='':
		for st in stops:
			if st in srstops:
				price = srst[st].split('=')[0]
				side = srst[st].split('=')[1]
				expires = int(round(time.time()) + 5)
				data = '{"filter":{"open":"true"},"count":"5","reverse":"true"}'
				headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'GET', '/api/v1/order', expires, data)
						}
				try:
					orders = s.get('https://www.bitmex.com/api/v1/order',headers=headers,data=data).json()
				except:
					orders = ''
				if orders !='':
					for o in orders:
						if 'e' in price:
							pass
						else:
							price = price.replace('.0','')
						if str(o['stopPx']) == price and o['side'] == side:
							expires = int(round(time.time()) + 5)
							data = '{"orderID":"'+o['orderID']+'"}'
							headers = {'content-type' : 'application/json',
									'Accept': 'application/json',
									'X-Requested-With': 'XMLHttpRequest',
									'api-expires': str(expires),
									'api-key': get_login(),
									'api-signature': generate_signature(get_passwd(), 'DELETE', '/api/v1/order', expires, data)}
							try:
								delor = s.delete('https://www.bitmex.com/api/v1/order',headers=headers,data=data)
							except:
								delor = ''
							if delor!='':
								stops.remove(st)
			else:
				pass
		with open('base.json','w') as file:
			data = {"orders":ordersF,
					"stoporders":stops}
			json.dump(data,file,indent=2,ensure_ascii=False)
	else:
		pass

def check_orders():
	with open('base.json','r') as file:
		base = json.load(file)
		stops = base['orders']
		ordersF = base['stoporders']
	try:
		r = requests.get('http://45.132.19.122/orders/limitsids.json')
		srstops = r.json()
	except:
		srstops = ''
	try:
		r = requests.get('http://45.132.19.122/orders/limitss.json')
		srst = r.json()
	except:
		srst = ''
	if srstops!='' and srst!='':
		for st in stops:
			if st in srstops:
				price = srst[st].split('=')[0]
				side = srst[st].split('=')[1]
				expires = int(round(time.time()) + 5)
				data = '{"filter":{"open":"true","ordType":"Limit"},"count":"5","reverse":"true"}'
				headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': generate_signature(get_passwd(), 'GET', '/api/v1/order', expires, data)
						}
				try:
					orders = s.get('https://www.bitmex.com/api/v1/order',headers=headers,data=data).json()
				except:
					orders = ''
				if orders!='':
					for o in orders:
						if 'e' in price:
							pass
						elif float(price)<1:
							pass
						else:
							price = price.replace('.0','')
						if str(o['price']) == price and o['side'] == side:
							expires = int(round(time.time()) + 5)
							data = '{"orderID":"'+o['orderID']+'"}'
							headers = {'content-type' : 'application/json',
									'Accept': 'application/json',
									'X-Requested-With': 'XMLHttpRequest',
									'api-expires': str(expires),
									'api-key': get_login(),
									'api-signature': generate_signature(get_passwd(), 'DELETE', '/api/v1/order', expires, data)}
							try:
								delor = s.delete('https://www.bitmex.com/api/v1/order',headers=headers,data=data)
							except:
								delor = ''
							if delor!='':
								stops.remove(st)
			else:
				pass
		with open('base.json','w') as file:
			data = {"orders":stops,
					"stoporders":ordersF}
			json.dump(data,file,indent=2,ensure_ascii=False)

def check_pos():
	try:
		r = requests.get('http://bgtrading.pro/orders/pos.json')
	except:
		r=''
	if r!='':
		data = r.json()
		for d in data:
			if d['crossMargin']==True:
				symbol=d['symbol']
				data= '{"filter":{"isOpen":true,"symbol":"'+symbol+'"}}'
				expires = int(round(time.time()) + 5)
				signature = generate_signature(get_passwd(), 'GET', '/api/v1/position', expires, data)
				headers = {'content-type' : 'application/json',
				'Accept': 'application/json',
				'X-Requested-With': 'XMLHttpRequest',
				'api-expires': str(expires),
				'api-key': get_login(),
				'api-signature': signature
				}
				try:
					r = requests.get('https://www.bitmex.com/api/v1/position',headers = headers,data=data).json()[0]
					acc = r['account']
				except:
					r = ''
					acc = ''
				if r!='' and acc!='':
					if r['crossMargin']!=True:
						data= '{"symbol":"'+symbol+'","leverage":0}'
						expires = int(round(time.time()) + 5)
						signature = generate_signature(get_passwd(), 'POST', '/api/v1/position/leverage', expires, data)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': signature
						}
						try:
							r = s.post('https://www.bitmex.com/api/v1/position/leverage',headers = headers,data=data).json()
						except:
							r = ''
					else:
						pass
			else:
				symbol=d['symbol']
				leverage = d['leverage']
				data= '{"filter":{"isOpen":true,"symbol":"'+symbol+'"}}'
				expires = int(round(time.time()) + 5)
				signature = generate_signature(get_passwd(), 'GET', '/api/v1/position', expires, data)
				headers = {'content-type' : 'application/json',
				'Accept': 'application/json',
				'X-Requested-With': 'XMLHttpRequest',
				'api-expires': str(expires),
				'api-key': get_login(),
				'api-signature': signature
				}
				try:
					r = requests.get('https://www.bitmex.com/api/v1/position',headers = headers,data=data).json()[0]
					acc = r['account']
				except:
					r = ''
					acc = ''
				if r!='' and acc!='':
					if r['leverage']!=leverage:
						data= '{"symbol":"'+symbol+'","leverage":'+leverage+'}'
						expires = int(round(time.time()) + 5)
						signature = generate_signature(get_passwd(), 'POST', '/api/v1/position/leverage', expires, data)
						headers = {'content-type' : 'application/json',
						'Accept': 'application/json',
						'X-Requested-With': 'XMLHttpRequest',
						'api-expires': str(expires),
						'api-key': get_login(),
						'api-signature': signature
						}
						try:
							r = s.post('https://www.bitmex.com/api/v1/position/leverage',headers = headers,data=data).json()
						except:
							r = ''
					else:
						pass

def check_opens():
	with open('base.json','r') as file:
		base = json.load(file)
		stops = base['orders']
		ordersF = base['stoporders']
	try:
		r = requests.get('http://45.132.19.122/orders/ordersids.json')
		srstops = r.json()
	except:
		srstops = ''
	try:
		r = requests.get('http://45.132.19.122/orders/orders.json')
		srst = r.json()
	except:
		srst = ''
	if srstops!='' and srst!='':
		for st in srstops:
			if st not in stops:
				try:
					tbalance = float(requests.get('http://45.132.19.122/orders/blc.json').text)
				except:
					tbalance = 0
				try:
					balance = get_balance()
				except:
					balance = 0
				if tbalance!=0 and balance!=0:
					symbol = srst[st].split('=')[0]
					side = srst[st].split('=')[1]
					tqty = srst[st].split('=')[2]
					price = srst[st].split('=')[3]
					try:
						znak = price.split('-')[-1]
					except:
						znak = ''
					if 'e-' in price:
						ordersumm = int(tqty)*((float(price.split('-')[0].replace('e','')))/(pow(10,int(znak))))
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)/((float(price.split('-')[0].replace('e','')))/(pow(10,int(znak)))))
					elif float(price)<1:
						ordersumm = round(int(tqty)*float(price),10)
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)/float(price))
					else:
						ordersumm = round(int(tqty)/float(price),10)
						percent = round((ordersumm*100)/(ordersumm+tbalance),2)
						qty = round(balance*(percent/100)*float(price))
					data = '{"symbol":"'+symbol+'","side":"'+side+'","orderQty":'+str(qty)+',"ordType":"Market"}'
					expires = int(round(time.time()) + 5)
					headers = {'content-type' : 'application/json',
					'Accept': 'application/json',
					'X-Requested-With': 'XMLHttpRequest',
					'api-expires': str(expires),
					'api-key': get_login(),
					'api-signature': generate_signature(get_passwd(), 'POST', '/api/v1/order', expires, data)
					}
					for i in range(3):
						try:
							res = s.post('https://www.bitmex.com/api/v1/order', headers=headers,data=data)
						except:
							res = ''
						if res!='':
							try:
								checkor = res.json()['orderID']
							except:
								checkor = ''
							if checkor!='':
								stops.append(st)
								break
							else:
								pass
						else:
							pass
			else:
				pass
		with open('base.json','w') as file:
			data = {"orders":stops,
					"stoporders":ordersF}
			json.dump(data,file,indent=2,ensure_ascii=False)

def on_closing():
	f_stop.set()
	if Thread().is_alive():
		Thread()._Thread__stop()
	sys.exit()
	window.destroy()

def online():
	try:
		r = requests.get('http://45.132.19.122/online.php?key='+get_login()+'&v='+version)
	except:
		pass
	data= '{"filter":{"isOpen":true}}'
	expires = int(round(time.time()) + 5)
	signature = generate_signature(get_passwd(), 'GET', '/api/v1/position', expires, data)
	headers = {'content-type' : 'application/json',
	'Accept': 'application/json',
	'X-Requested-With': 'XMLHttpRequest',
	'api-expires': str(expires),
	'api-key': get_login(),
	'api-signature': signature
	}
	try:
		r = s.get('https://www.bitmex.com/api/v1/position',headers = headers,data=data)
		positions = str(len(r.json()))
	except:
		positions = 'Неизвестно'
	try:
		r = requests.get('http://bgtrading.pro/system/pos.php?key='+get_key()+'&count='+positions)
	except:
		pass

def run(Obj,window,b):
    checkkey = 0
    try:
        checkkey = check_key()
    except:
        notif.config(text='Сервер недоступен')
    if checkkey == 1:
        notif.config(text='Ключ проверен')
        notif.config(text='Идет отключение...',bg='black')
        Obj['run'] = not Obj['run']
        if Obj['run']:
            # f(f_stop)
            save_auth()
            capi = 0
            try:
            	capi = check_api()
            except:
            	pass
            if capi == 1:
                notif.config(text='API проверено')
                b.config(text='Бот запущен',bg='green')
                startB.config(state='active')
                capi = 0
                while Obj['run']:
                    if check_update():
                        Obj['run'] = not Obj['run']
                        window.quit()
                        break
                    try:
                        capi = check_api()
                    except:
                        pass
                    if capi == 1:
                        online()
                        do()    
                        sleep(10)
                        notif.config(text='',bg='black')
                    else:
                        notif.config(text='Биржа недоступна',bg='black')
                b.config(text='Бот отключен',bg='red')
                f_stop.set()
        else:
            pass
        if Thread().is_alive():
            Thread()._Thread__stop()
    else:
        notif.config(text='Ключ отсутствует в базе!')

def check_api():
	control = 0
	expires = int(round(time.time()) + 5)
	headers = {'content-type' : 'application/json',
	'Accept': 'application/json',
	'X-Requested-With': 'XMLHttpRequest',
	'api-expires': str(expires),
	'api-key': get_login(),
	'api-signature': generate_signature(get_passwd(), 'GET', '/api/v1/user', expires, '')
	}
	r = s.get('https://www.bitmex.com/api/v1/user',headers = headers).json()
	try:
		idu = r['id']
		control = 1
	except:
		pass
	try:
		idu = r['error']['message']
		control = 0
		notif.config(text=idu)
	except:
		pass
	return control

def _onKeyRelease(event):
    ctrl  = (event.state & 0x4) != 0
    if event.keycode==88 and  ctrl and event.keysym.lower() != "x": 
        event.widget.event_generate("<<Cut>>")

    if event.keycode==86 and  ctrl and event.keysym.lower() != "v": 
        event.widget.event_generate("<<Paste>>")

    if event.keycode==67 and  ctrl and event.keysym.lower() != "c":
        event.widget.event_generate("<<Copy>>")

def main():
    check_sc()
    global window
    window = Tk()
    window.geometry('420x200')
    window.resizable(False, False)
    window.iconbitmap('ic.ico')
    window.title('BGTrading v1.0 b'+version)
    window.config(bg='black')
    window.bind_all("<Key>", _onKeyRelease, "+")
    label_key = Label(window,text='Ваш ключ:',bg='black',fg='#FFD700')
    label_key.place(x='10',y='10',height='24')
    Key = Entry(window,width='33')
    Key.insert(0,get_key())
    Key.place(x='80',y='10',height='24')
    getkey = Button(window,text='Скопировать ключ',bg='black',fg='#FFD700',command=get_key1)
    getkey.place(x='290',y='10')
    global login
    login = StringVar()
    global password
    password = StringVar()
    login_entry = Entry(window,width='150',textvariable=login)
    login_entry.event_add('<<Paste>>', '<Control-Igrave>')
    login_entry.insert(0,get_login())
    pass_entry = Entry(window,width='150',textvariable=password)
    pass_entry.insert(0,get_passwd())
    label_login = Label(window,text='API KEY',fg='#FFD700',bg='black')
    label_pass = Label(window,text='API SECRET',fg='#FFD700',bg='black')
    label_login.place(y='40',x='10',height='24')
    login_entry.place(y='65',x='10',width='160')
    label_pass.place(y='90',x='10',height='24')
    pass_entry.place(y='115',x='10',width='160')
    saveb = Button(window,width=15,text='Сохранить',bg='black',fg='#FFD700',command=save_auth)
    saveb.place(y='140',x='30')
    Obj = dict(run=False)
    global notif
    notif = Label(window,bg='black',fg='#FFD700')
    notif.place(y='150',x='275')
    global update
    update = Label(window,bg='black',fg='#FFD700',cursor="hand2")
    update.place(y='175',x='10')
    update.bind("<Button-1>", callback)
    b = Label(window,text='Бот отключен',bg='red',fg='white')
    b.place(y='75',x='275')
    global startB
    if api_key != '' and api_secret != '':
        startB = Button(window, text='start/stop',bg='black',fg='#FFD700', command=lambda: Thread(target=run,args=(Obj,window,b)).start())
        startB.invoke()
        startB.place(y='105',x='280')
        startB.config(stat='disabled')
    else:
        startB = Button(window, text='start/stop',bg='black',fg='#FFD700', command=lambda: Thread(target=run,args=(Obj,window,b)).start())
        startB.place(y='105',x='280')
    Label(window,text='vk.com/akidok',bg='black',fg='white').place(y='230',x='170')
    window.protocol("WM_DELETE_WINDOW", on_closing)
    window.mainloop()
# ClI3PFa6sL0ITQrdtmADvExB
# naZqeEIiWRl1DJ_sJr-J8LRQvJh15ZXdXauOOxywFFgwc5Em
    # with open('C:\\OSpanel\\OSPanel\\domains\\localhost\\orders\\data.json','w') as file:
    #   json.dump(orders[0],file,indent=2,sort_keys=True,ensure_ascii=False,default=str)

if __name__ == '__main__':
	main()