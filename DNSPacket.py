"""
Represents a DNS packet. Will build a query to send to server, or parse through a server's response.
"""

import struct
from util import bytes_to_str, insertBytes


RCODE = {0: 'No error. The request completed successfully.',
         1: 'Format error. The name server was unable to interpret the query.',
         2: 'Server failure. The name server was unable to process this query due to a problem with the name server.',
         3: 'Name Error. Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.',
         4: 'Not Implemented. The name server does not support the requested kind of query.',
         5: 'Refused. The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.',
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
    TYPE_A = 1
    TYPE_CNAME = 5
    HEADER_LEN = 12

    default_header = bytes.fromhex('0001 0100 0001 0000 0000 0000')
    # dnssec needs to have the OPT additional RR included
    default_dnssec_header = bytes.fromhex('0001 0100 0001 0000 0000 0001')

    def __init__(self):
        self.header = bytearray(DNSPacket.HEADER_LEN)


    def createDnsHeader(self, num_questions, num_answers, num_ns, num_additional):
        return struct.pack(
            '!HHHHHH',
            1,  # just use an ID of 1
            # The flags section. "0x0100" will assert the "recursion desired" bit, and leave everything else at 0
            0x0100,
            num_questions,
            num_answers,
            num_ns,
            num_additional,
        )

    #def createQuestionRR(self, )

    # Factory method to return a DNSPacket
    # Create a new DNSPacket for a query. The type can be set using parameters
    @classmethod
    def newQuery(cls, url, question_type, using_dnssec=False):
        packet = cls()
        # Fill out the "question" or "query" section.
        url_split = url.split('.')

        # First, get the header
        if using_dnssec:
            header = packet.createDnsHeader(1, 0, 0, 1)
        else:
            header = packet.createDnsHeader(1, 0, 0, 0)

        # Create the QNAME section, which holds the url. This consists of number of labels, one for each domain.
        # Each label is 1 byte telling the # of characters in the next domain, then the ASCII bytes 0x00 ends the section
        question_qname = bytearray(len(url) + 2)
        i = 0
        for domain in url_split:
            question_qname[i] = len(domain)
            i += 1
            insertBytes(question_qname, domain.encode('utf-8', 'strict'), i)
            i += len(domain)
        print("question_qname:", question_qname)
        question_bytes = struct.pack("!{0}sHH".format(len(question_qname)), question_qname, question_type, 1)
        print("question_bytes:", question_bytes)

        packet.bytes = header + question_bytes
        return packet

    # Factory method to return a DNSPacket
    # Can be called with a byte-string received from networking interface
    # Will parse a bytes object representing a DNS packet. Fields in the DNSPacket will be filled in.
    @classmethod
    def newFromBytes(cls, b, packet_id=0):
        packet = cls()


        # TESTING: Figuring out struct stuff here
        # ! = indicates "network" byte order and int sizes
        # H = unisigned short, 2 bytes
        # B = unsigned char, 1 byte
        print("len =", len(b))
        (s_id, s_temp, s_qdcount, s_ancount, s_nscount, s_arcount) = struct.unpack("!HHHHHH", b[:12])
        print(s_id, s_temp, s_qdcount, s_ancount, s_nscount, s_arcount)

        # First parse out the header
        packet.id = int.from_bytes(b[:2], 'big')
        if packet_id != 0 and packet.id != packet_id:
            print("ERROR\tID " + str(packet.id) + " Does not match. Expected " + str(packet_id))
        temp = int.from_bytes(b[2:4], 'big')
        packet.qr = temp & 2**15 == 1
        packet.opcode = temp >> 11 & 15
        packet.aa = temp >> 10 & 1 == 1
        packet.tc = temp >> 9 & 1 == 1
        packet.rd = temp >> 8 & 1 == 1
        packet.ra = temp >> 7 & 1 == 1
        packet.z = temp >> 6 & 1 == 1
        packet.ad = temp >> 5 & 1 == 1
        packet.cd = temp >> 4 & 1 == 1
        packet.rcode = temp & 15
        if packet.rcode != 0 and packet.rcode in RCODE:
            if packet.rcode == 3:
                print("NOTFOUND")
                return packet
            else:
                print("ERROR\t" + RCODE[packet.rcode])
                return
        elif packet.rcode != 0:
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
        print("ID =", packet.id)
        print("num_questions =", packet.num_questions)
        print("num_answers =", packet.num_answers)
        print("num_authority_records =", packet.num_authority_records)
        print("num_additional_records =", packet.num_additional_records)
        print("QR: ", packet.qr)
        print("Opcode: ", packet.opcode)
        print("AA: ", packet.aa)

        i = cls.HEADER_LEN
        # Parse through question section. We aren't interested in the data here, just move to the answer section
        # Can't just skip it, because the 'name' part of this section is not a defined length
        for _ in range(packet.num_questions):
            # First get through the name section
            if (b[i] >> 6) == 0b11:
                # If the first two bits of the 'name' field are 1, then there is a pointer here, not the actual name.
                #  just move past it
                # print("Found a pointer to name")
                i += 2
            else:
                # Not a pointer.. move i past this string
                num_bytes = b[i]
                while num_bytes != 0:
                    i += 1 + num_bytes
                    num_bytes = b[i]
                i += 1
                # Just skip past the rest of the question section
                i += 4

        # print("-- Now reading answers --")
        # Parse answers:


        packet.answers = []
        for _ in range(packet.num_answers):
            answer = {}
            if (b[i] >> 6) == 0b11:
                # Name is stored as a 2-byte pointer. We will just ignore this for now
                # print("Name is stored as a pointer")
                i += 2
            else:
                # Not a pointer.. parse out the string
                reading_domain_string = True
                domain = []
                while reading_domain_string:
                    num_bytes = b[i]
                    # print("num_bytes =", num_bytes)
                    i += 1
                    if num_bytes == 0:
                        # A zero byte means the domain part is done
                        # print("Done reading domain")
                        reading_domain_string = False
                    else:
                        domain.append(b[i: i + num_bytes])
                        i += num_bytes
                        # print("Read domain:", domain[len(domain) - 1].decode('utf-8'))


            # ! = indicates "network" byte order and int sizes
            # I = unsigned int, 4 bytes
            # H = unisigned short, 2 bytes
            # B = unsigned char, 1 byte
            (answer['type'], answer['class'], answer['ttl'], answer['rdata_len']) = struct.unpack("!HHIH", b[i:i+10])
            print("Type:", answer['type'], b[i:i + 2])
            print("Class:", answer['class'], b[i:i + 2])
            print("TTL:", answer['ttl'], b[i:i + 4])
            print("rdata len:", answer['rdata_len'], b[i:i + 2])
            i += 10


            if answer['type'] == cls.TYPE_A:
                if answer['rdata_len'] == 4:
                    answer['ip_addr'] = b[i:i + 4]
                    i += 4
                    # TODO: Not sure if auth//noauth thing is supposed to be like this
                    print("IP\t{0}.{1}.{2}.{3}\t{4}".format(answer['ip_addr'][0], answer['ip_addr'][1], answer['ip_addr'][2],
                                                       answer['ip_addr'][3], "auth" if packet.aa else "noauth"))
                    


                else:
                    print("Error\trdata length should be 4")
                    return
            elif answer['type'] == cls.TYPE_CNAME:
                if answer['rdata_len'] + i > len(b):
                    print("Error\trdata_len is out of bounds")
                # TODO: Not sure if auth//noauth thing is supposed to be like this
                print("CNAME\t" + bytes_to_str(b[i+1: i + answer['rdata_len']]) + "\t" + ("auth" if packet.aa else "noauth"))
                i += answer['rdata_len']

            packet.answers.append(answer)
        return packet



    # Builds and returns an OPT RR record. The record can then be copied into the main buffer.
    def createOptRecord(self):
        # TODO: the name should be "0 (root domain)", does that just mean a 1-byte zero?
        return struct.pack(
            '!BHHIH', # I am not including the RDATA field!
            # name label. In this case we are referring to the "root domain", which means a 0-length string
            0,
            41,  # TYPE = OPT
            # This is the "Class" field. In opt records it is used for the requested UDP payload size.
            # Up this if there are fragmentation issues
            1024,
            # This is the "TTL" field. In opt records the D0 flag goes here, and the rest is zero'd
            0x80000000,
            0,  # length of RDATA section
            #0,  # Not included because rdata length is 0!
        )


# For testing
if __name__ == '__main__':
    DNSPacket.newFromBytes(DNSPacket.default_header)
