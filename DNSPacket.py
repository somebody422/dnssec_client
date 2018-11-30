"""
Represents a DNS packet. Will build a query to send to server, or parse through a server's response.
"""

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

    def __init__(self):
        self.header = bytearray(DNSPacket.HEADER_LEN)

    # Factory method to return a DNSPacket
    # Create a new DNSPacket for a query. The type can be set using parameters
    @classmethod
    def newQuery(cls, url, question_type):
        packet = cls()
        # Fill out the "question" or "query" section.
        url_split = url.split('.')
        # QNAME section has length len(url)+2. The rest of the query section is 4 bytes
        packet.query_bytes = bytearray(len(url) + 6)

        # First, fill in QNAME section, which holds the url. This consists of number of labels, one for each domain.
        # Each label is 1 byte telling the # of characters in the next domain, then the ASCII bytes 0x00 ends the
        # section
        i = 0
        for domain in url_split:
            packet.query_bytes[i] = len(domain)
            i += 1
            insertBytes(packet.query_bytes, domain.encode('utf-8', 'strict'), i)
            i += len(domain)
        packet.query_bytes[i] = 0x00
        i += 1
        # Next comes the QTYPE section:
        insertBytes(packet.query_bytes, question_type.to_bytes(2, byteorder='big'), i)
        i += 2
        # The QCLASS section. This should always be 1
        insertBytes(packet.query_bytes, bytes([0, 1]), i)
        # i += 2

        packet.bytes = DNSPacket.default_header + packet.query_bytes
        return packet

    # Factory method to return a DNSPacket
    # Can be called with a byte-string received from networking interface
    # Will parse a bytes object representing a DNS packet. Fields in the DNSPacket will be filled in.
    @classmethod
    def newFromBytes(cls, b, packet_id=0):
        packet = cls()
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

            answer['type'] = int.from_bytes(b[i:i + 2], 'big')
            # print("Type:", answer['type'], b[i:i + 2])
            i += 2

            answer['class'] = int.from_bytes(b[i:i + 2], 'big')
            # print("Class:", answer['class'], b[i:i + 2])
            i += 2

            answer['ttl'] = int.from_bytes(b[i:i + 4], 'big')
            # print("TTL:", answer['ttl'], b[i:i + 4])
            i += 4

            answer['rdata_len'] = int.from_bytes(b[i:i + 2], 'big')
            # print("rdata len:", answer['rdata_len'], b[i:i + 2])
            i += 2

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


# For testing
if __name__ == '__main__':
    DNSPacket.newFromBytes(DNSPacket.default_header)
