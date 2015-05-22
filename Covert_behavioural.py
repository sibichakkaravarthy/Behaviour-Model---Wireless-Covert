#!/usr/bin/python

# Copyright (c) 2015 Sibi Chakkaravarthy Sethuraman and Vaidehi Vijayakumar
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#try:
import scapy
import ctypes
#except ImportError:
   # del scapy
    #fron scapy import all as scapy
import datetime
import sys
from scapy.all import *

FakeAPThresold = 5
global timestampDict
global timestampCount
deauthCount=0
deauthThreshold=5
START=5
global radiotapTalbe

#detects fake access points which use random timestamp field by comparing timestamp
#and maitaining count
def MonitorFakeAP(pkt):
    global FakeAPThresold
    global timestampDict
    global timestampCount
    if(pkt.type==0 and pkt.subtype==8):
        bssid=pkt.addr2
        ssid=pkt.info
	essid=pkt.addr3
        timestamp=pkt.timestamp
        if bssid not in timestampDict:
            timestampDict[bssid]=timestamp
            timestampCount[bssid]=0
        elif (timestamp <= timestampDict[bssid]):
            timestampCount[bssid]+=1
            if timestampCount[bssid] > FakeAPThresold :
                print ("Detected Fake Access Point for ssid '%s'" %(ssid))
                print ("attacker node identity '%s'" %(bssid))
        timestampDict[bssid]=timestamp

#detecting deauth DOS attack by keeping count of deauth packets
def MonitorDeauth(pkt):
    global deauthCount
	#sender=pkt.getlayer(Dot11).addr2
    if((pkt.type==0) and (pkt.type==2)and (pkt.subtype==8) and (pkt.subtype==12)):
        bssid=pkt.addr2
	sender=pkt.getlayer(Dot11).addr2
        deauthCount+=1
        diff = datetime.datetime.now()-start
        if((diff.seconds > START) and ((deauthCount/diff.seconds) > deauthThreshold)):
            print ("Detected AIReplay against : "+pkt.addr2)
            print ("Detected AIReplay against : "+pkt.addr1)
	    print ("Detected AIReplay against : "+pkt.addr3)

		#print ("attacker node identity '%s'" %(sender))

#maintain radiotap header for each sender
def MaintainRadiotapTable(pkt):
    global radiotapTable
    if(pkt.getlayer(Dot11).type==2):
        radiotap=str(pkt)[:pkt.getlayer(RadioTap).len]
        sender=pkt.getlayer(Dot11).addr2
        if sender not in radiotapTable:
            radiotapTable[sender]=radiotap

#monitor change in radiotap header in deauth packets
def MonitorDeauth2(pkt):
    sender=pkt.getlayer(Dot11).addr2
	#attacker=pkt.getlayer(Dot11).addr3
    radiotap=str(pkt)[:pkt.getlayer(RadioTap).len]
    if sender in radiotapTable:
        radiotap2=radiotapTable[sender]
        if radiotap2!=radiotap:
            print ("Detected WLAN-wifi attack in particular AP : %s "%(pkt.getlayer(Dot11).addr2))
            print ("Detected Aireplay attack : by the client : : : %s :::"%(pkt.getlayer(Dot11).addr1))
	#if attacker in radiotapTable:
	#radiotap2=radiotapTable[attacker]
		#if radiotap3!=radiotap:
	    #print ("Detected Aireplay attack : by the client : : : %s :::"%(pkt.getlayer(Dot11).addr3))

def IDS(pkt):
    if(pkt.haslayer(Dot11)):
        if(pkt.getlayer(Dot11).type==2):
            MaintainRadiotapTable(pkt)
        if((pkt.getlayer(Dot11).type==0) and (pkt.getlayer(Dot11).subtype==12)):
            MonitorDeauth(pkt.getlayer(Dot11)) #detect for deauth attack
            MonitorDeauth2(pkt) #detect for deauth attack by monitoring change in radiotap header
        if(pkt.getlayer(Dot11).type==0 and pkt.getlayer(Dot11).subtype==8):
            MonitorFakeAP(pkt.getlayer(Dot11)) #detect fake access points




timestampDict= {}
timestampCount={}
radiotapTable={}
start=datetime.datetime.now()
#sniff(iface=sys.argv[2],prn=IDS)
sniff(iface='mon0',prn=IDS)
sniff(iface='wlan0',prn=IDS)
