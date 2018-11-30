"""
A few unit tests
"""

import unittest
from DNSPacket import DNSPacket

class TestDNSPacket(unittest.TestCase):

	def test_DNSStaticValues(self):
		self.assertEqual(DNSPacket.TYPE_A, 1)
		self.assertEqual(DNSPacket.TYPE_CNAME, 5)
		self.assertEqual(DNSPacket.HEADER_LEN, 12)

	def test_buildTypeAQuery(self):
		url = 'test.com'
		packet = DNSPacket.newQuery(url, DNSPacket.TYPE_A)
		self.assertTrue(packet.bytes[:12] == DNSPacket.default_header)
		self.assertEqual(len(packet.bytes), 12 + len(url) + 6)

	def test_buildPacketFromBytes(self):
		b = bytes.fromhex('00 01 81 80 00 01 00 01  00 00 00 00 02 63 73 03  72 69 74 03 65 64 75 00  00 01 00 01 c0 0c 00 01   00 01 00 00 05 0b 00 04   81 15 1e 68 ')
		#print(b)
		packet = DNSPacket.newFromBytes(b)
		self.assertEqual(packet.id, 1)
		self.assertEqual(packet.num_questions, 1)
		self.assertEqual(packet.num_answers, 1)
		#self.assertEqual(packet.answers[0].domain, ['rit','edu'])
		self.assertEqual(packet.answers[0]['type'], 1)
		self.assertEqual(packet.answers[0]['rdata_len'], 4)


	def test_test(self):
		pass

if __name__ == '__main__':
	unittest.main()
