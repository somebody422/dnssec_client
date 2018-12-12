"""
Represents a DNS packet. Will build a query to send to server, or parse through a server's response.
"""
import struct

from records.Record import parse_record
import records.Record
from util import *

RCODE = {0: 'No error. The request completed successfully.',
         1: 'Format error. The name server was unable to interpret the query.',
         2: 'Server failure. The name server was unable to process this query due to a problem with the name server.',
         3: 'Name Error. Meaningful only for responses from an authoritative name server, this code signifies that '
            'the domain name referenced in the query does not exist.',
         4: 'Not Implemented. The name server does not support the requested kind of query.',
         5: 'Refused. The name server refuses to perform the specified operation for policy reasons. For example, '
            'a name server may not wish to provide the information to the particular requester, or a name server may '
            'not wish to perform a particular operation (e.g., zone transfer) for particular data.',
         6: 'YXDomain. Name Exists when it should not.',
         7: 'YXRRSet. RR Set Exists when it should not.',
         8: 'NXRRSet. RR Set that should exist does not.',
         9: 'NotAuth. Server Not Authoritative for zone.',
         10: 'NotZone. Name not contained in zone.',
         11: 'BADVERS.Bad OPT Version. -OR- BADSIG.TSIG Signature Failure.',
         12: 'BADKEY. Key not recognized.',
         13: 'BADTIME. Signature out of time window.',
         14: 'BADMODE. Bad TKEY Mode.',
         15: 'BADNAME. Duplicate key name.',
         16: 'BADALG. Algorithm not supported.',
         17: 'BADTRUNC. Bad truncation.'}


class DNSPacket:
    RR_TYPE_A = 1
    RR_TYPE_CNAME = 5
    RR_TYPE_DNSKEY = 48
    RR_TYPE_DS = 43
    RR_TYPE_RRSIG = 46

    # https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    ALGO_TYPE_RSASHA1 = 5
    ALGO_TYPE_RSASHA256 = 8

    HEADER_LEN = 12

    def __init__(self):
        self.header = bytearray(DNSPacket.HEADER_LEN)
        self.name = b''

    @classmethod
    def newQuery(cls, url, question_type, using_dnssec=False):
        """
        Create a new DNSPacket for a query. The type can be set using parameters.
        :param url: url to query
        :param question_type: type of record being requested
        :param using_dnssec: True is using dnssec, false otherwise
        :return: The constructed DNS query packet
        """
        packet = cls()

        question = packet.createQuestion(url, question_type)

        if using_dnssec:
            header = packet.createDnsHeader(1, 0, 0, 1)
            packet.bytes = header + question + packet.createOptRecord()
        else:
            header = packet.createDnsHeader(1, 0, 0, 0)
            packet.bytes = header + question

        return packet

    @classmethod
    def newFromBytes(cls, b, packet_id=0):
        """
        Will parse a bytes object representing a DNS packet. Fields in the DNSPacket will be filled in.
        :param b: byte-string usually received from networking interface
        :param packet_id: expected ID of the packet
        :return: The packet if successful, None otherwise
        """
        packet = cls()
        packet.bytes = b

        # First parse out the header
        if packet.parse_header(b, packet_id) is None:
            return
        # Not really interested in authority_records or additional_records
        # print("ID =", packet.id)
        # print("num_questions =", packet.num_questions)
        # print("num_answers =", packet.num_answers)
        # print("num_authority_records =", packet.num_authority_records)
        # print("num_additional_records =", packet.num_additional_records)
        # print("QR: ", packet.qr)
        # print("Opcode: ", packet.opcode)
        # print("AA: ", packet.aa)

        # Parse through question section. We aren't interested in the data here, just move to the answer section
        # Can't just skip it, because the 'name' part of this section is not a defined length
        answers_start_i = packet.skip_questions(b)

        # Parse answers:
        packet.parse_answers(b[answers_start_i:])
        return packet

    def skip_questions(self, b):
        """
        Returns the first index after the question section
        :param b: Bytes of packet
        :return: Int representing the first index after the question section
        """
        count = self.HEADER_LEN
        for _ in range(self.num_questions):
            if count == self.HEADER_LEN:
                temp = parse_name(b[count:])
                count += temp[0]
                for s in temp[1]:
                    self.name += s
            else:
                count += skip_name(b[count:])
            count += 4  # Skip Type and Class
        return count

    def parse_answers(self, b):
        """
        Parses the answer section and returns a list of records
        :param b: Bytes of packet
        :return: A list of records
        """
        self.answers = []
        count = 0
        for _ in range(self.num_answers):
            result = parse_record(b[count:])
            if isinstance(result[1], records.Record.RRSigRecord):
                result[1].signer_name = self.name
            elif len(result[1].name) == 2:
                result[1].name = self.expand_name(b, result[1].name)
            count += result[0]
            print(result[1])
            self.answers.append(result[1])

    def createDnsHeader(self, num_questions, num_answers, num_ns, num_additional):
        return struct.pack(
            '!HHHHHH',
            0x0001,  # just use an ID of 1
            # The flags section. "0x0130" will set the "recursion desired" bit,
            # the Authenticated data (AD) bit, and the Checking Disabled (CD) bit.
            # See https://mycourses.rit.edu/d2l/le/713074/discussions/threads/2901592/View
            0x0130,
            num_questions,
            num_answers,
            num_ns,
            num_additional,
        )

    # Builds and returns an OPT RR record. The record can then be copied into the main buffer.
    def createOptRecord(self):
        # TODO: the name should be "0 (root domain)", does that just mean a 1-byte zero?
        return struct.pack(
            '!BHHHHH',  # I am not including the RDATA field!
            # name label. In this case we are referring to the "root domain", which means a 0-length string
            0,
            41,  # TYPE = OPT
            # This is the "Class" field. In opt records it is used for the requested UDP payload size.
            # Up this if there are fragmentation issues
            4024,
            0, # Sets ERcode and EDNS0 version to 0 (no idea what they are for)
            # This is the "TTL" field. In opt records the D0 flag goes here, and the rest is zero'd
            0x8000,
            0,  # length of RDATA section
            # 0,  # Not included because rdata length is 0!
        )

    def createQuestion(self, url, question_type):
        # Create the QNAME section, which holds the url. This consists of number of labels, one for each domain. Each
        # label is 1 byte telling the # of characters in the next domain, then the ASCII bytes 0x00 ends the section
        question_qname = bytearray(len(url) + 2)
        i = 0
        for domain in url.split('.'):
            question_qname[i] = len(domain)
            i += 1
            insertBytes(question_qname, domain.encode('utf-8', 'strict'), i)
            i += len(domain)

        # The last 2 bytes is "class" which should always be 1 for "internet"
        return struct.pack("!{0}sHH".format(len(question_qname)), question_qname, question_type, 1)

    def dump(self):
        dump_packet(self.bytes)

    def parse_header(self, b, packet_id=0):
        # First parse out the header
        self.id = int.from_bytes(b[:2], 'big')
        if packet_id != 0 and self.id != packet_id:
            print("ERROR\tID " + str(self.id) + " Does not match. Expected " + str(packet_id))
        temp = int.from_bytes(b[2:4], 'big')
        self.qr = temp & 2 ** 15 == 1
        self.opcode = temp >> 11 & 15
        self.aa = temp >> 10 & 1 == 1
        self.tc = temp >> 9 & 1 == 1
        self.rd = temp >> 8 & 1 == 1
        self.ra = temp >> 7 & 1 == 1
        self.z = temp >> 6 & 1 == 1
        self.ad = temp >> 5 & 1 == 1
        self.cd = temp >> 4 & 1 == 1
        self.rcode = temp & 15
        if self.rcode != 0:
            if self.rcode == 3:
                print("NOTFOUND")
            elif self.rcode in RCODE:
                print("ERROR\t" + RCODE[self.rcode])
            else:
                print("ERROR\tRcode " + str(self.rcode) + " unrecognized")
            return

        # More stuff, not sure if needed
        self.num_questions = int.from_bytes(b[4:6], 'big')
        self.num_answers = int.from_bytes(b[6:8], 'big')
        self.num_authority_records = int.from_bytes(b[8:10], 'big')
        self.num_additional_records = int.from_bytes(b[10:12], 'big')
        self.questions = []
        self.answers = []
        return self

    def expand_name(self, data, pointer):
        return self.name



# For testing
# if __name__ == '__main__':
# DNSPacket.newFromBytes(DNSPacket.default_header)
