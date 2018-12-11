"""
Represents a DNS packet. Will build a query to send to server, or parse through a server's response.
"""
import binascii
import struct
from util import *
from datetime import datetime
from base64 import b64encode

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

    HEADER_LEN = 12

    def __init__(self):
        self.header = bytearray(DNSPacket.HEADER_LEN)

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

    # Factory method to return a DNSPacket
    # Can be called with a byte-string received from networking interface
    # Will parse a bytes object representing a DNS packet. Fields in the DNSPacket will be filled in.
    @classmethod
    def newFromBytes(cls, b, packet_id=0):
        packet = cls()
        packet.bytes = b

        # First parse out the header
        packet.id = int.from_bytes(b[:2], 'big')
        if packet_id != 0 and packet.id != packet_id:
            print("ERROR\tID " + str(packet.id) + " Does not match. Expected " + str(packet_id))
        temp = int.from_bytes(b[2:4], 'big')
        packet.qr = temp & 2 ** 15 == 1
        packet.opcode = temp >> 11 & 15
        packet.aa = temp >> 10 & 1 == 1
        packet.tc = temp >> 9 & 1 == 1
        packet.rd = temp >> 8 & 1 == 1
        packet.ra = temp >> 7 & 1 == 1
        packet.z = temp >> 6 & 1 == 1
        packet.ad = temp >> 5 & 1 == 1
        packet.cd = temp >> 4 & 1 == 1
        packet.rcode = temp & 15
        if packet.rcode != 0:
            if packet.rcode == 3:
                print("NOTFOUND")
            elif packet.rcode in RCODE:
                print("ERROR\t" + RCODE[packet.rcode])
            else:
                print("ERROR\tRcode " + str(packet.rcode) + " unrecognized")
            return

        # More stuff, not sure if needed
        packet.num_questions = int.from_bytes(b[4:6], 'big')
        packet.num_answers = int.from_bytes(b[6:8], 'big')
        packet.num_authority_records = int.from_bytes(b[8:10], 'big')
        packet.num_additional_records = int.from_bytes(b[10:12], 'big')
        packet.questions = []
        packet.answers = []
        # Not really interested in authority_records or additional_records
        # print("ID =", packet.id)
        # print("num_questions =", packet.num_questions)
        # print("num_answers =", packet.num_answers)
        # print("num_authority_records =", packet.num_authority_records)
        # print("num_additional_records =", packet.num_additional_records)
        # print("QR: ", packet.qr)
        # print("Opcode: ", packet.opcode)
        # print("AA: ", packet.aa)

        i = cls.HEADER_LEN

        # Parse through question section. We aren't interested in the data here, just move to the answer section
        # Can't just skip it, because the 'name' part of this section is not a defined length
        for _ in range(packet.num_questions):
            i += skip_name(b[i:])
            i += 4  # Skip Type and Class

        # Parse answers:
        packet.answers = []
        for _ in range(packet.num_answers):
            result = packet.parse_record(b[i:])
            i += result[0]
            packet.answers.append(result[1])
        return packet

    def parse_record(self, bytes):
        print("==== Record: ====")
        answer = {}
        i = 0
        if (bytes[i] >> 6) == 0b11:
            # Name is stored as a 2-byte pointer. We will just ignore this for now
            print("Name is stored as a pointer")
            i += 2
        else:
            # Not a pointer.. parse out the string
            reading_domain_string = True
            domain = []
            while reading_domain_string:
                num_bytes = bytes[i]
                # print("num_bytes =", num_bytes)
                i += 1
                if num_bytes == 0:
                    # A zero byte means the domain part is done
                    # print("Done reading domain")
                    reading_domain_string = False
                else:
                    domain.append(bytes[i: i + num_bytes])
                    i += num_bytes
                    print("Read domain:", domain[len(domain) - 1].decode('utf-8'))
        # The raw bytes of the name field
        answer['raw_name'] = bytes[:i]
        #answer['name'] = domain

        # ! = indicates "network" byte order and int sizes
        # I = unsigned int, 4 bytes
        # H = unisigned short, 2 bytes
        # B = unsigned char, 1 byte
        (answer['type'], answer['class'], answer['ttl'], answer['rdata_len']) = struct.unpack("!HHIH", bytes[i:i + 10])
        answer['rdata'] = bytes[i:10:]

        # print("Type:", answer['type'], bytes[i:i + 2])
        # print("Class:", answer['class'], bytes[i:i + 2])
        # print("TTL:", answer['ttl'], bytes[i:i + 4])
        # print("rdata len:", answer['rdata_len'], bytes[i:i + 2])
        i += 10

        if answer['type'] == self.RR_TYPE_A:
            if answer['rdata_len'] == 4:
                answer['ip_addr'] = bytes[i:i + 4]
                # TODO: Not sure if auth//noauth thing is supposed to be like this
                print("IP\t{0}.{1}.{2}.{3}\t{4}".format(answer['ip_addr'][0], answer['ip_addr'][1],
                                                        answer['ip_addr'][2],
                                                        answer['ip_addr'][3], "auth" if self.aa else "noauth"))
            else:
                print("Error\trdata length should be 4 for A records")
                return
        elif answer['type'] == self.RR_TYPE_CNAME:
            if answer['rdata_len'] + i > len(bytes):
                print("Error\trdata_len is out of bounds")
            # TODO: Not sure if auth//noauth thing is supposed to be like this
            print("CNAME\t" + bytes_to_str(bytes[i + 1: i + answer['rdata_len']]) + "\t" + (
                "auth" if self.aa else "noauth"))
        elif answer['type'] == self.RR_TYPE_DNSKEY:
            count = i
            answer['flags'] = bytes[count:count+2]  # TODO: print contents of flags
            # The 'SEP' bit indicates that the DS record in the parent zone uses this key!
            # 'SEP' = Secure Entry Point
            answer['sep'] = answer['flags'][1] & (1)
            count += 2
            answer['protocol'] = ord(bytes[count:count+1])
            count += 1
            answer['algorithm'] = ord(bytes[count:count + 1])
            count += 1
            answer['key'] = str(b64encode(bytes[count:i+answer['rdata_len']]), 'utf-8')
            print("DNSKEY: flags={}, sep={}, protocol={}, algorithm={}, key={}".format(answer['flags'], answer['sep'], answer['protocol'], answer['algorithm'], answer['key']))
        elif answer['type'] == self.RR_TYPE_RRSIG:
            count = i + 2
            answer['type_covered'] = struct.unpack("!H", bytes[i:count])[0]
            answer['algorithm'] = ord(bytes[count:count + 1])
            count += 1
            answer['labels'] = ord(bytes[count:count + 1])
            count += 1
            answer['orig_ttl'] = struct.unpack("!I", bytes[count:count + 4])[0]
            count += 4
            answer['expiration'] = datetime.fromtimestamp(struct.unpack("!I", bytes[count:count + 4])[0])
            if answer['expiration'] < datetime.today():
                print("ERROR\tSignature has expired============================")

            count += 4
            answer['inception'] = datetime.fromtimestamp(struct.unpack("!I", bytes[count:count + 4])[0])
            count += 4
            answer['tag'] = struct.unpack("!H", bytes[count:count + 2])[0]
            count += 2
            count += skip_name(bytes[count:])  # TODO: Get signer's name
            answer['signature'] = str(b64encode(bytes[count:i+answer['rdata_len']]), 'utf-8')
            print("RRSIG: type_covered={}, algorithm={}, labels={}, orig_ttl={}, expiration={}, inception={}, tag={}k, signature={}".format(answer['type_covered'], answer['algorithm'], answer['labels'], answer['orig_ttl'], answer['expiration'], answer['inception'], answer['tag'], answer['signature']))
        elif answer['type'] == self.RR_TYPE_DS:
            count = i + 2
            answer['key_id'] = int(struct.unpack("!H", bytes[i:count])[0])
            answer['algorithm'] = ord(bytes[count:count + 1])
            count += 1
            answer['digest_type'] = ord(bytes[count:count + 1])
            count += 1
            answer['digest'] = str(binascii.hexlify(bytes[count:i+answer['rdata_len']]), 'utf-8').upper()
            print("DS: key_id={}, algorith={}, digest_type={}".format(answer['key_id'], answer['algorithm'], answer['digest_type'], answer['digest']))

        i += answer['rdata_len']
        return i, answer

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

# For testing
# if __name__ == '__main__':
# DNSPacket.newFromBytes(DNSPacket.default_header)
