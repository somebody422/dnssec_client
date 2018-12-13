"""

The hashing and sha stuff

"""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from util import insertBytes

"""
Puts together data for an RRSet and computes hash
https://tools.ietf.org/html/rfc4034#section-3.1.8.1
"""


def createRRSetHash(rr_set, rrsig_record, domain):
    data = rrsig_record.type_covered.to_bytes(2, 'big') + \
           rrsig_record.algorithm.to_bytes(1, 'big') + rrsig_record.labels.to_bytes(1, 'big') + \
           rrsig_record.orig_ttl.to_bytes(4, 'big') + rrsig_record.expiration + \
           rrsig_record.inception + rrsig_record.tag.to_bytes(2, 'big') + \
           rrsig_record.signer_name

    for rr in rr_set:
        data += RRSignableData(rr, domain, rrsig_record.orig_ttl)

    return data


"""
A DS record is just the hash of a public key
Uses SHA256
"""


def createDSRecord(dnskey, domain):
    data = formatName(domain)

    data += dnskey.rdata

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


def RRSignableData(rr, owner, orig_ttl):
    # TODO: Should the name stay in pointer format? Here i am using labels.
    formatted_owner = formatName(owner)
    # print("formatted_owner:", formatted_owner)
    # print("ttl:", rr['ttl'])
    # print("type:", rr['type'])
    return formatted_owner + rr.type.to_bytes(2, 'big') + rr.clazz.to_bytes(2, 'big') + \
           orig_ttl.to_bytes(4, 'big') + rr.rdata_len.to_bytes(2, 'big') + rr.rdata


def verify_signature(signature, key, recordset):
    expo, mod = get_expo_and_mod(key)
    constructed_key = RSA.construct((mod, expo))
    cipher = PKCS1_v1_5.new(constructed_key)
    return cipher.verify(SHA256.new(recordset), signature)


def get_expo_and_mod(dnskey):
    data = bytearray(dnskey.key)
    cursor = 1
    expo_len = int.from_bytes([data[0]], 'big')
    if expo_len == 0:
        expo_len = int.from_bytes(data[1:3], 'big')
        cursor = 3
    expo = int.from_bytes(data[cursor:cursor + expo_len], 'big')
    cursor += expo_len
    mod = int.from_bytes(data[cursor:], 'big')
    return expo, mod
