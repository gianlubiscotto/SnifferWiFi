#!/usr/bin/env python
# coding=utf-8
import sys
import os
from threading import Thread, Lock
from time import *
from scapy.all import *
from netaddr import *
from netaddr.core import *
import signal
import socket
import netifaces
import requests
import json
import errno
import urllib2, urllib
import mysql.connector
from datetime import datetime
from scapy.layers.dot11 import Dot11, Dot11Elt

'''
mydb = mysql.connector.connect(
host="192.168.1.5",
user="pi",
passwd="raspberry",
database="CinqueTerre")
'''

myId = 1
totAggrJ = {'MacReali' : 0 , 'MacRandom' : 0}
sql_struct = []
id_antenna = 1
old_reali = 0
old_random = 0
canc_reali = 0
canc_random = 0
lock = Lock()

x=netifaces.interfaces()
iface=""
for interface in x:
	if(len(interface)>len(iface)):
		iface=interface


#dizionario con tutti gli oui registrati. Aggiornato al 14 luglio 2018
oui_list={}
with open('nmap-mac-prefixes2019.txt') as f:
	for line in f:
		key,val=line.split('\t')
		oui_list[key]=val


#estrae il sequence number
def EstractSN(sc): 
	hexSC = '0' * (4 - len(hex(sc)[2:])) + hex(sc)[2:] 	#toglie le prime due perche hex(pkt.SC) ha 0x davanti
	sn = int(hexSC[:-1], 16)				#non considera l'ultima cifra
	return sn

#conta il numero di mac reali(local bit a 0) e quanti randomici
def ContaDet(MappaSig):
	veri = 0
	random = 0
	for k in MappaSig.keys() :
		for q in MappaSig[k].keys():			
			if (MappaSig[k][q]['RandomMac'])!= True:	#se non è segnato come random (local bit a 1)
				veri = veri +1				#aumenta il conto dei veri
			else:
				random = random+1			#altrimenti aumenta il conto dei random
	return 'Mac reali: ' , veri , '\t'+'Mac random: ' , random  

def ContaDetJ(MappaSig): 
	veri = 0
	random = 0
	for k in MappaSig.keys() :
		for q in MappaSig[k].keys():			
			if (MappaSig[k][q]['RandomMac'])!= True:
				veri = veri +1
			else:
				random = random+1
	return  {'MacReali' : veri , 'MacRandom' : random}  
				

def CalcDist (sq1 , sq2):
	if sq1 > 25 and sq2 >25 and sq1 < 4080 and sq2 < 4080 :
		return abs(sq1 - sq2)
	else:
		return abs( (sq1 % 4080) - (sq2 % 4080) )

#controllo degli ssid in comune
def SsidMatch( mac1 , mac2):
	global listaAp
	setSsidComuni = set(listaAp)
	set1 = set(mac1['ssids']) - setSsidComuni
	set2 = set(mac2['ssids']) - setSsidComuni
	
	return  len(set1)> 0 and  len(set1 & set2)/len(set1) == 1 

#cancella il mac più vecchio e estende il log di quello più nuovo  
def Aggrega( mac1 , macaddr1 , mac2 , macaddr2 ):
	global canc_random
	print "aggrego"
	if mac1['myid'] < mac2['myid']: #(mac1['log'][-1]['time'] < mac2['log'][-1]['time']):
		print "cancello il primo"
		mac1['canc'] = True
		canc_random = canc_random+1
		for x in mac2['log']:
			mac1['log'].append(x)
		mac2['log']= mac1['log']
		mac2['pastMac'] = list(set(mac2['pastMac']) | set(mac1['pastMac']) | set ([macaddr1]) )
	else:
		print "cancello il secondo"
		mac2['canc'] = True
		canc_random = canc_random+1
		for x in mac1['log']:
			mac2['log'].append(x)
		mac1['log']= mac2['log']
		mac1['pastMac'] = list(set(mac2['pastMac']) | set(mac1['pastMac']) | set ([macaddr2])  )

#controlla se i due mac siano da aggregare
def Compara( mac1 , macaddr1 , mac2 , macaddr2 ): #mac1=>set1 mac2=>set2
	print mac1['log']
	print mac2['log']
	
	if mac1['uuid'] != '' and mac1['uuid'] == mac2['uuid']:
		print "controllo su uuid"
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)
		return True;

	elif SsidMatch(mac1 , mac2):	#se hanno tutti gli ssid in comune li aggrego 
		print "controllo ssid"
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2) #segno che quello più vecchio è da cancellare
		return True;
	
	elif abs(mac1['log'][0]['time']- mac2['log'][-1]['time']) < 7  and abs(mac1['log'][0]['pow']- mac2['log'][-1]['pow']) < 10  :	#il time del primo log del mac i e il time dell'ultimo log del mac j siano distanti meno di 2 secondi e che le due potenze differiscano poco
		print "controllo mac1log0-mac2log-1 e potenza"
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)
		return True;
	
	elif abs(mac1['log'][-1]['time']- mac2['log'][0]['time']) < 7  and abs(mac1['log'][-1]['pow']- mac2['log'][0]['pow']) < 10  :
		print "controllo mac1log-1-mac2log0 e potenza"		
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)	
		return True;

	elif CalcDist(mac1['log'][-1]['seq'] , mac2['log'][0]['seq']) < 25 and abs(mac1['log'][-1]['time']- mac2['log'][0]['time']) < 7:
		print "controllo mac1log-1-mac2log0 sq e time"				
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)	
		return True;

	elif CalcDist(mac1['log'][0]['seq'] , mac2['log'][-1]['seq']) < 25 and abs(mac1['log'][0]['time']- mac2['log'][-1]['time']) < 7:
		print "controllo mac1log0-mac2log-1 sq e time"						
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)	
		return True;

	elif CalcDist(mac1['log'][0]['seq'] , mac2['log'][-1]['seq']) < 20 and abs(mac1['log'][0]['pow']- mac2['log'][-1]['pow']) < 10  :
		print "controllo sn e potenza"
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)
		return True;
	
	elif CalcDist(mac1['log'][-1]['seq'] , mac2['log'][0]['seq']) < 20 and abs(mac1['log'][-1]['pow']- mac2['log'][0]['pow']) < 10  :
		print "controllo sn e potenza"
		Aggrega(mac1 , macaddr1 , mac2 , macaddr2)
		return True;
	return False;


#ritorna il numero di layer nel pkt
def LengthDot11Elt(pkt): 
	ie_l = 0
	while Dot11Elt in pkt:
		p = pkt[Dot11Elt]
		ie_l  = ie_l + 1
		pkt=p.payload
	return ie_l;

def hasOneRandom(sign):
	for q in sign.keys():
		if (sign[q]['RandomMac'])== True:
			return True;
	return False;

# ritorna un numero n indicante l' n-ennesimo mac address randomico trovato
def putMyId (packet):	
	global myId
	tmp = -1
	if isRandomMac(packet):
		tmp = myId
		myId = myId + 1
	return tmp; 
	
#guarda che il local bit sia settato a 1 (facendo l'and con 2=0010)
def isRandomMac(packet):
	return int(packet.addr2[1:2],16)&2>0; 
#controlla se il CID è quello di Google
def isRandomAndroid(packet):
	return packet.addr2[0:8] == 'da:a1:19';

def getLog(packet):
	return { 'time' : packet.time , 'pow' : -(256-ord(packet.notdecoded[-4:-3])) , 'seq' : EstractSN(packet.SC)  };

#signature unica per modello di dispositivo
def getSignature(packet):
	ie_l = LengthDot11Elt(packet) 
	i = 0
	sig= 'probe:'
    	pp=packet
    	#probe: id dei layer in ordine di apparizione(separati da virgole),
	while Dot11Elt in packet and i < ie_l -1:
		temp = pp[Dot11Elt]
		sig=sig+str(temp.ID)+','
		pp=temp.payload
		i = i+1
        
	i=0
	value221=''
	value45=''
	value191=''
	value127=''
	sig33=''
	sig221=''
	sig45=''
	sig191=''
	sig127=''
	txpow=''

	pp=packet
	while Dot11Elt in packet and i < ie_l -1:
		pkt = pp[Dot11Elt]
		#221(id del vendor es. 0050f2,subtype es. 08),
		if pkt.ID == 221 and len(pkt.info)>2:
			value221=''
			for rate in range(0 , 3):
				value221 = value221 + '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2) 
			sig221=sig221+'221('+value221+','+'{0:0{1}X}'.format(ord(pkt.info[3:4]),2)+'),'
		    
		#htcap: capabilities bitmask da HT Capabilities Information Element (id 45),
		#httag: AMPDU Parameters bitmask from an HT Capabilities Information Element (id 45), 
		#htmcs:RX Supported Modulation and Coding Scheme bitmask from an HT Capabilities Information Element (id 45),
		if pkt.ID== 45:
			for rate in range(0 , pkt.len):
				value45=value45+ '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
		    	bin45=''
			for x in value45:
				bin45=bin45+ '{0:04b}'.format(int(x,16))
			bin45=bin45[24:101]+'000'
			print bin45
			intero24104=int(bin45,2)
			print intero24104
			htmcs=hex(intero24104)[2:-1]
			print htmcs	
			sig45='htcap:'+value45[0:2*2]+',httag:'+value45[2*2:3*2]+',htmcs:'+htmcs+','

		#vhtcap:capabilities bitmask from the optional VHT Capabilities Information Element, if it is present (id 191),
		#vhtrxmcs:RX MCS Map (id 191), 
		#vhttxmcs:TX MCS Map from the VHT Supported MCS Set field from a VHT Capabilities Information Element (id 191), 
		if pkt.ID== 191:
		    for rate in range(0 , pkt.len):
			value191=value191+ '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
		    sig191='vhtcap:'+value191[0:8]+',vhtrxmcs:'+value191[8:12]+',vhttxmcs:'+value191[16:20]+','
		  
		#txpow: minimum and maximum power values from a Power Capability IE,
		if pkt.ID== 33:
		    for rate in range(0 , pkt.len):
			txpow=txpow+ '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
		    sig33=txpow
		 
		#extcap:Extended Capabilities IE (id 127), 
		if pkt.ID== 127:
		    for rate in range(0 , pkt.len):
			value127=value127+ '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
		    sig127='extcap:'+value127  
		    
		pp=pkt.payload
		i = i+1

	sig=sig+sig221+sig45+sig191+sig33+sig127
	return sig

#se esiste, ritorna l'uuid del pacchetto
def getUuid(packet):
	ie_l = LengthDot11Elt(packet)	#numero di layer	
	i = 0
	value = ''
	while Dot11Elt in packet and i < ie_l -1:
		
		pkt = packet[Dot11Elt]	#layer information elements 
		if pkt.ID == 221 and len(pkt.info)>3:	#layer relativo al vendor
			if ord(pkt.info[3:4]) == 4 : #prende la quarta cifra di info relativa al vendor e controlla che sia 4(end of transmission)
				index = 4
				while index < (pkt.len-4):
					subtag = '{0:0{1}X}'.format(ord(pkt.info[index:index+1]),2) + '{0:0{1}X}'.format(ord(pkt.info[index+1:index+2]),2)
					if  subtag == '1047':	#se la quinta+sesta cifra è uguale a 1047 allora segno l'uuid
						for rate in range( index + 4 , index + 19):
							value = value + '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
						index = pkt.len
					try:					
						index  = index +  ord(pkt.info[index+3:index+4]) + 4
					except TypeError:
						index = pkt.len
		packet=pkt.payload
		i = i+1
		
	return value;

#ritorna una lista dei NOMI dei vendor del pacchetto. Se non ha nessun layer vendor torna una lista vuota, se ha layer vendor ma non sono riconosciuti sostituisce ZZZZZZ (6 Z)
def getVendorStrList(packet): 
	venList = []
	ie_l = LengthDot11Elt(packet) 	
	i = 0
	while Dot11Elt in packet and i < ie_l -1:
		value = ''
		pkt = packet[Dot11Elt]
		if pkt.ID == 221 and len(pkt.info)>2:
			for rate in range(0 , 3):
				value = value + '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
			try:
				#oui = OUI(value) #aggiunge i trattini
				#value = oui.registration().org
				value=oui_list[value]			
			except IndexError:
				value = 'NotRegistered'
			if value == '':
				value='Unknown'		
			venList.append('{:Z<6}'.format(value))

		packet=pkt.payload
		i = i+1	
	return venList;

#controlla che almeno uno dei layer vendor riporti come primi 3 caratteri di info l'oui di Apple
def isVendorApple(packet):	
	
	ie_l = LengthDot11Elt(packet) 	
	i = 0
	while Dot11Elt in packet and i < ie_l -1:
		value = ''
		pkt = packet[Dot11Elt]
		if pkt.ID == 221 and len(pkt.info)>2:
			for rate in range(0 , 3):
				value = value + '{0:0{1}X}'.format(ord(pkt.info[rate:rate+1]),2)
			try:
				#oui = OUI(value)	#aggiunge i trattini				
				#if 'APPLE' in oui.registration().org.upper():
				if 'APPLE' in oui_list[value].upper():
					return True
 			except IndexError:
				value=''
		packet=pkt.payload
		i = i+1	
	return False;



SigList = {}
ApList = {} 
listaAp = [] #per controllo ssid comuni

def PacketHandler(pkt) :
#	os.system('clear')	
	global listaAp
	global totAggrJ 
	global sql_struct
	global old_reali
	global old_random
	global canc_reali
	global canc_random
	if pkt.haslayer(Dot11) :
  
        	#beacon frame (quello che manda l'ap periodicamente per segnalare la sua presenza)
		if pkt.type == 0 and pkt.subtype == 8 :   
			ApList[pkt.addr2]= pkt.info
			listaAp.append(pkt.info)

        	#probe request e controllo che la potenza sia > -99 => -(256-ord(pkt.notdecoded[-4:-3])=potenza=>RSSI)
		if pkt.type == 0 and pkt.subtype == 4 and -(256-ord(pkt.notdecoded[-4:-3])) > -99 :
			key = getSignature(pkt)

			if (SigList.has_key(key)): #se la signature derivata dal modello è presente nella mia lista
				if (SigList[key].has_key(pkt.addr2)):	#e ha anche associato il macaddr2 appena rilevato
					if pkt.info !='' and pkt.info not in SigList[key][pkt.addr2]['ssids']:	
						SigList[key][pkt.addr2]['ssids'].append(pkt.info)

					SigList[key][pkt.addr2]['log'].append(getLog(pkt)) #aggiorno il log
					if getUuid(pkt) != '':	
						SigList[key][pkt.addr2]['uuid'] = getUuid(pkt)
				else:	#la signature che era presente non ha il macaddr2 sniffato ora
					ssids_list = []
					if pkt.info != '':
						ssids_list.append(pkt.info)
					#assegno in corrispondenza di questo nuovo macaddr2 il set di informazioni
					SigList[key][pkt.addr2] = { 'RandomMac' :  isRandomMac(pkt) , 'RandomAndroid' : isRandomAndroid(pkt) , 'VendorApple' : isVendorApple(pkt) , 'ssids' : ssids_list , 'ouis' : getVendorStrList(pkt) , 'log' : [getLog(pkt)] , 'uuid' : getUuid(pkt) , 'myid': putMyId(pkt) , 'canc' : False , 'pastMac' : [] }	
					
				
			else:	#ho scoperto una nuova signature
				ssids_list = []
				if pkt.info != '':
					ssids_list.append(pkt.info)
				#assegno in corrispondenza di questa nuova signature,il macaddr2 e il set di prima
				SigList[key] = { pkt.addr2 : { 'RandomMac' :  isRandomMac(pkt) , 'RandomAndroid' : isRandomAndroid(pkt)  , 'ssids' : ssids_list , 'VendorApple' : isVendorApple(pkt) , 'ouis' : getVendorStrList(pkt) , 'log' : [getLog(pkt)]  , 'uuid' : getUuid(pkt)  , 'myid': putMyId(pkt), 'canc' : False  , 'pastMac' : []  } }
				
				#controllo se la signature di un reale è stata trasmessa in modo errato (quella errata è più lunga)
				if not isRandomMac(pkt):	#il mac deve essere vero		
					for k in SigList.keys():	
						if k!=key:
							for q in SigList[k].keys():
								if q==pkt.addr2:	#il mac appena rilevato era già presente sotto un'altra signature

									if len(k)<len(key):	#avevo salvato la chiave giusta e aggiorno il log
										if pkt.info !='' and pkt.info not in SigList[k][pkt.addr2]['ssids']:	
											SigList[k][pkt.addr2]['ssids'].append(pkt.info)
										SigList[k][pkt.addr2]['log'].append(getLog(pkt)) 
										if getUuid(pkt) != '':	
											SigList[k][pkt.addr2]['uuid'] = getUuid(pkt)	
										SigList.pop(key,None)
									else:	#avevo salvato la signature errata
										print SigList[key]
										print SigList[k][q]
										SigList[key]={pkt.addr2: SigList[k][q]}		
										if pkt.info !='' and pkt.info not in SigList[key][pkt.addr2]['ssids']:	
											SigList[key][pkt.addr2]['ssids'].append(pkt.info)
										SigList[key][pkt.addr2]['log'].append(getLog(pkt)) 
										if getUuid(pkt) != '':	
											SigList[key][pkt.addr2]['uuid'] = getUuid(pkt)	
										SigList[k].pop(q , None)
										if not SigList[k]:
											SigList.pop(k,None)
				
				#controllo se la signature di un random è stata trasmessa in modo errato (quella errata è più corta)				
				if isRandomMac(pkt):	#il mac deve essere random		
					for k in SigList.keys():	
						if k!=key:
							for q in SigList[k].keys():
								if q==pkt.addr2:	#il mac appena rilevato era già presente sotto un'altra signature

									if len(k)>len(key):	#avevo salvato la chiave giusta e aggiorno il log
										if pkt.info !='' and pkt.info not in SigList[k][pkt.addr2]['ssids']:	
											SigList[k][pkt.addr2]['ssids'].append(pkt.info)
										SigList[k][pkt.addr2]['log'].append(getLog(pkt)) 
										if getUuid(pkt) != '':	
											SigList[k][pkt.addr2]['uuid'] = getUuid(pkt)	
										SigList.pop(key,None)
									else:	#avevo salvato la signature errata
										print SigList[key]
										print SigList[k][q]
										SigList[key]={pkt.addr2: SigList[k][q]}		
										if pkt.info !='' and pkt.info not in SigList[key][pkt.addr2]['ssids']:	
											SigList[key][pkt.addr2]['ssids'].append(pkt.info)
										SigList[key][pkt.addr2]['log'].append(getLog(pkt)) 
										if getUuid(pkt) != '':	
											SigList[key][pkt.addr2]['uuid'] = getUuid(pkt)	
										SigList[k].pop(q , None)
										if not SigList[k]:
											SigList.pop(k,None)
	totNonAggr = ContaDet(SigList)	#torna una stringa indicando il numero di reali e di random
	
	print "======================================="	
	for k in SigList.keys():
		print k
		for q in SigList[k]:
			print q
			if SigList[k][q]['uuid']!='':
				print SigList[k][q]['uuid']
	print ""


	
	#aggregazione dei random
	for k in SigList.keys() :
		for q in SigList[k].keys():
			if (SigList[k][q]['RandomMac'])== True and (SigList[k][q]['canc']) == False :
				for w in SigList[k].keys():
					if (SigList[k][w]['RandomMac'])== True and w != q  and (SigList[k][w]['canc']) == False :
						print "comparo",q, w
						Compara(SigList[k][q] , q , SigList[k][w] , w);
						
							
	#cancello i vecchi mac
	for k in SigList.keys():
		for q in SigList[k].keys():
			if SigList[k][q]['RandomMac']==True:
				if abs(SigList[k][q]['log'][-1]['time'] - time.time()) > 20:
					SigList[k][q]['canc'] = True
					canc_random = canc_random+1
					print "cancello random per vecchiaia",q
			else:
				if abs(SigList[k][q]['log'][-1]['time']-time.time()) > 30:
					SigList[k][q]['canc']=True
					canc_reali = canc_reali+1
					print 'cancello global per vecchiaia',q 

	#cancello mac aggregati e o vecchi
	for k in SigList.keys() :
		for q in SigList[k].keys():
			if (SigList[k][q]['canc'])== True:
				print "cancello perchè aggregato o vecchio",q
				if SigList[k][q]['RandomMac']==True:
					random = -1
					reali = 0
				else:
					reali = -1
					random = 0
				timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				sublist = []
				sublist.append(id_antenna)
				sublist.append(q)
				sublist.append(reali)
				sublist.append(random)
				sublist.append(int(totAggrJ['MacReali']))
				sublist.append(int(totAggrJ['MacRandom']))
				sublist.append(timestamp)
				sql_struct.append(sublist)
				SigList[k].pop(q , None)		
				if not SigList[k]:
					SigList.pop(k,None)
	
	totAggr = ContaDet(SigList)
	
	totAggrJ = ContaDetJ(SigList)

	#os.system('clear')
	reali = int(totAggrJ['MacReali']) + canc_reali - old_reali
	random = int(totAggrJ['MacRandom']) + canc_random - old_random
	if pkt.addr2 is not None :
		if (reali != 0) or (random != 0):
			timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			sublist = []
			sublist.append(id_antenna)
			sublist.append(pkt.addr2)
			sublist.append(reali)
			sublist.append(random)
			sublist.append(int(totAggrJ['MacReali']))
			sublist.append(int(totAggrJ['MacRandom']))
			sublist.append(timestamp)
			sql_struct.append(sublist)
	print (totAggr)
	print (totNonAggr)	
	old_reali = int(totAggrJ['MacReali'])
	old_random = int(totAggrJ['MacRandom'])
	canc_reali = 0
	canc_random = 0
	'''os.system('clear')'''
	
class ThreadInvio():
	def __init__(self):
		self._running = True
	def terminate(self):
		self._running = False


	def run(self):
		global totAggrJ
		global sql_struct
		global lock
		while True:
			time.sleep(60)
			try:
					'''
					cursor = mydb.cursor()
					sql = "INSERT INTO Persone (id_antenna, macaddr, reali, random, now_reali, now_random, time) VALUES (%s, %s, %s, %s, %s, %s, %s)"
					lock.acquire()
					for l in sql_struct: 
						val = (l[0], l[1], l[2], l[3], l[4], l[5], l[6])
						cursor.execute(sql, val)
						print(cursor.rowcount, "record insert")
						mydb.commit()
					print("Inviato\n")
					del sql_struct[:]
					lock.release()
					'''
					lock.acquire()
					#connessione al db per registrare i dati
					for l in sql_struct:	
						userdata = {'Id' : l[0] , 'now_reali' : l[4] , 'now_random' : l[5] , 'time' : l[6] , 'macaddr' : l[1] , 'delta_reali' : l[2] , 'delta_random' : l[3]}
						resp = requests.post('http://sniffer5terre.altervista.org/php/gestione_dativ3.php', params=userdata)
						print("Inviato")
					del sql_struct[:]
					#print "DIMENSIONE SQLSTRUCT POST ELIMINAZIONE: " , asizeof(sql_struct)
					lock.release()
			except requests.exceptions.RequestException as e:
                		print("Errore invio")
			
class ThreadSniffing():
	def __init__(self):
		self._running = True
	def terminate(self):
		self._running = False
	def run(self):
		sniff(iface=iface,prn = PacketHandler )

class ThreadCancella():
	def __init__(self):
			self._running = True
	def terminate(self):
			self._running = False
	def run(self):
		global listaAp
		global sql_struct
		global SigList 
		global ApList  
		global listaAp 
		global old_reali
		global old_random
		global lock
		time.sleep(60)
		lock.acquire()
		del sql_struct[:]
		SigList.clear()
		ApList.clear()
		del listaAp[:]
		old_reali = 0
		old_random = 0
		lock.release()

			
				
		

        
Invio = ThreadInvio()
Sniffer = ThreadSniffing()
Cancella = ThreadCancella()

InvioT = Thread(target = Invio.run)
SnifferT = Thread(target = Sniffer.run)
CancellaT = Thread(target = Cancella.run)

InvioT.start()
SnifferT.start()
CancellaT.start()


