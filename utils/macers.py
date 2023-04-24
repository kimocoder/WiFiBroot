import sys
import os
import random

class org:

	def __init__(self, bssid=''):
		self.bssid = bssid
		self.org = self.findORG(self.bssid)

	def findORG(self, bssid):
		with open(f'{os.getcwd()}/utils/macers.txt', 'r') as file__:
			for line in file__.readlines():
				if (
					line.strip('\n').split(' ~ ')[0].lower()
					== f"{bssid.lower()[:9]}xx:xx:xx"
				):
					file__.close()
					return line.strip('\n').split(' ~ ')[1].split(' ')[0]
		return 'unknown'

	def supports_color():	
		plat = sys.platform
		supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)
		# isatty is not always implemented, #6223.
		is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
		return bool(supported_platform and is_a_tty)

	def randomness(self, _max, last_num):
		_to_return = last_num
		while _to_return == _to_return:
			_to_return = random.randint(1, _max)
		return _to_return

class Modes:

	def get_mode(self, m):
		avail_modes = (1, 2, 3, 4)
		return m in avail_modes