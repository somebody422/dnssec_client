"""
Contains Record types and methods for manipulating records
"""
import binascii
import struct
import DNSPacket
from datetime import datetime
from base64 import b64encode

from util import parse_name, skip_name, ts_to_dt


class Record:
    def __init__(self, name, type, clazz, ttl, rdata_len, rdata):
        self.name = name
        self.type = type
        self.clazz = clazz
        self.ttl = ttl
        self.rdata_len = rdata_len
        self.rdata = rdata


class ARecord(Record):
    def __init__(self, name, type, clazz, ttl, rdata_len, rdata,
                 ip_addr, auth):
        assert rdata_len == 4
        Record.__init__(self, name, type, clazz, ttl, rdata_len, rdata)
        self.ip_addr = ip_addr
        self.auth = auth

    def __str__(self):
        return "IP\t{0}.{1}.{2}.{3}".format(self.ip_addr[0],
                                            self.ip_addr[1],
                                            self.ip_addr[2],
                                            self.ip_addr[3])


class DNSKeyRecord(Record):
    def __init__(self, name, type, clazz, ttl, rdata_len, rdata,
                 flags, protocol, algorithm, key):
        Record.__init__(self, name, type, clazz, ttl, rdata_len, rdata)
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.key = key

    def is_sep(self):
        return int.from_bytes(self.flags, 'big') >> 31 == 1

    def printable_key(self):
        return str(b64encode(self.key), encoding="utf-8")

    def __str__(self):
        return "DNSKEY\t{}\t{}\t{}\t{}".format(int.from_bytes(self.flags, "big"), self.protocol, self.algorithm, self.printable_key())


class RRSigRecord(Record):
    def __init__(self, name, type, clazz, ttl, rdata_len, rdata,
                 type_covered, algorithm, labels, orig_ttl, expiration, inception, tag, signer_name, signature):
        super().__init__(name, type, clazz, ttl, rdata_len, rdata)
        self.type_covered = type_covered
        self.algorithm = algorithm
        self.labels = labels
        self.orig_ttl = orig_ttl
        self.expiration = expiration
        assert ts_to_dt(expiration) > datetime.today()
        self.inception = inception
        assert ts_to_dt(inception) < datetime.today()
        self.tag = tag
        self.signer_name = signer_name
        self.signature = signature

    def printable_signature(self):
        return str(b64encode(self.signature), encoding="utf-8")

    def __str__(self):
        return "RRSIG\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(
            DNSPacket.DNSPacket.record_type_name[self.type_covered], self.algorithm, self.labels, self.orig_ttl,
            ts_to_dt(self.expiration), ts_to_dt(self.inception), self.tag, self.printable_signature())


class DSRecord(Record):
    def __init__(self, name, type, clazz, ttl, rdata_len, rdata,
                 key_id, algorithm, digest_type, digest):
        super().__init__(name, type, clazz, ttl, rdata_len, rdata)
        self.key_id = key_id
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest

    def printable_digest(self):
        return str(binascii.hexlify(self.digest), 'utf-8').upper()

    def __str__(self):
        return "DS\t{}\t{}\t{}\t".format(self.key_id, self.algorithm, self.digest_type, self.printable_digest())


def parse_record(bytes):
    """
    Parses a record
    :param bytes: The bytes starting at a record
    :return: a record
    """
    i, name = parse_name(bytes)

    # ! = indicates "network" byte order and int sizes
    # I = unsigned int, 4 bytes
    # H = unisigned short, 2 bytes
    # B = unsigned char, 1 byte
    (type, clazz, ttl, rdata_len) = struct.unpack("!HHIH", bytes[i:i + 10])
    i += 10
    rdata = bytes[i: i + rdata_len]

    if type == DNSPacket.DNSPacket.RR_TYPE_A:
        if rdata_len == 4:
            ip_addr = bytes[i:i + 4]
            return i + rdata_len, ARecord(name, type, clazz, ttl, rdata_len, rdata, ip_addr, "noauth")
        else:
            print("Error\tINVALID RDATA LEN FOR A RECORD")
            return
    elif type == DNSPacket.DNSPacket.RR_TYPE_DNSKEY:
        count = i
        flags = bytes[count:count + 2]
        count += 2
        protocol = ord(bytes[count:count + 1])
        count += 1
        algorithm = ord(bytes[count:count + 1])
        count += 1
        key = bytes[count:i + rdata_len]
        return i + rdata_len, DNSKeyRecord(name, type, clazz, ttl, rdata_len, rdata, flags, protocol, algorithm, key)
    elif type == DNSPacket.DNSPacket.RR_TYPE_RRSIG:
        count = i + 2
        type_covered = struct.unpack("!H", bytes[i:count])[0]
        algorithm = ord(bytes[count:count + 1])
        count += 1
        labels = ord(bytes[count:count + 1])
        count += 1
        orig_ttl = struct.unpack("!I", bytes[count:count + 4])[0]
        count += 4
        expiration = bytes[count:count + 4]
        count += 4
        inception = bytes[count:count + 4]
        count += 4
        tag = struct.unpack("!H", bytes[count:count + 2])[0]
        count += 2
        name_len = skip_name(bytes[count:])  # TODO: Get signer's name
        signer_name = bytes[count:count+name_len]
        count += name_len
        signature = bytes[count:i + rdata_len]
        return i + rdata_len, RRSigRecord(name, type, clazz, ttl, rdata_len, rdata, type_covered, algorithm, labels,
                                          orig_ttl, expiration, inception, tag, signer_name, signature)
    elif type == DNSPacket.DNSPacket.RR_TYPE_DS:
        count = i + 2
        key_id = int(struct.unpack("!H", bytes[i:count])[0])
        algorithm = ord(bytes[count:count + 1])
        count += 1
        digest_type = ord(bytes[count:count + 1])
        count += 1
        digest = bytes[count:i + rdata_len]
        return i + rdata_len, DSRecord(name, type, clazz, ttl, rdata_len, rdata, key_id, algorithm, digest_type, digest)
    else:
        return i + rdata_len, None


def print_record(record, rrsig, valid):
    print("{}\t{}\t{}".format(record, rrsig, "VALID" if valid else "INVALID"))
