"""

The hashing and sha stuff

"""
from Crypto.PublicKey import RSA

from util import insertBytes
import struct
import DNSPacket
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

"""
Puts together data for an RRSet and computes hash
https://tools.ietf.org/html/rfc4034#section-3.1.8.1
"""


def createRRSetHash(rr_set, rr_sig_header, domain):
    data = rr_sig_header
    for rr in rr_set:
        data += RRSignableData(rr, domain)

    hasher = SHA256.new()
    hasher.update(data)
    return hasher.digest()


"""
Puts a domain name into that form DNS loves so much

name: A domain name string
"""


def formatName(name):
    name_bytes = bytearray(len(name) + 2)

    i = 0
    for domain in name.split('.'):
        name_bytes[i] = len(domain)
        i += 1
        insertBytes(name_bytes, domain.encode('utf-8', 'strict'), i)
        i += len(domain)
    name_bytes[i] = 0
    return name_bytes


"""
Maybe rename this into something that makes more sense

This will take a RR and return the bytes to be used in signing
# RFC on signiture calculation: https://tools.ietf.org/html/rfc4034#section-3.1

owner is the domain owner (EX: 'example.com', 'com'). This TECHNICALLY should
be in the rr, but we never figured out the pointer name storage thing
"""


def RRSignableData(rr, owner):
    # TODO: Should the name stay in pointer format? Here i am using labels.
    formatted_owner = formatName(owner)
    # print("formatted_owner:", formatted_owner)
    # print("ttl:", rr['ttl'])
    # print("type:", rr['type'])
    return struct.pack("{0}sHHIH{1}s ".format(len(formatted_owner), rr.rdata_len), formatted_owner, rr.type, rr.clazz,
                       rr.ttl, rr.rdata_len, rr.rdata)


def verify_signature(signature, key, recordset):
    expo, mod = get_expo_and_mod(key)
    constructed_key = RSA.construct((mod, expo))
    cipher = PKCS1_v1_5.new(constructed_key)
    return cipher.verify(SHA256.new(recordset), signature)


def get_expo_and_mod(key):
    data = bytearray(key)
    cursor = 1
    expo_len = int.from_bytes([data[0]], 'big')
    if expo_len == 0:
        expo_len = int.from_bytes(data[1:3], 'big')
        cursor = 3
    expo = int.from_bytes(data[cursor:cursor + expo_len], 'big')
    cursor += expo_len
    mod = int.from_bytes(data[cursor:], 'big')
    return expo, mod


def make_sig(RRSig, rr_set):
    pass
