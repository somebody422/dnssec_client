"""

The hashing and sha stuff

"""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from util import insertBytes


def createRRSetData(rr_set, rrsig_record, domain):
    """
    Puts together data for an RRSet and computes hash
    https://tools.ietf.org/html/rfc4034#section-3.1.8.1
    :param rr_set: The RRset
    :param rrsig_record: The RRSIG record
    :param domain: The domain name of the RRSIG
    :return: The data ready for verification
    """
    data = rrsig_record.type_covered.to_bytes(2, 'big') + \
           rrsig_record.algorithm.to_bytes(1, 'big') + rrsig_record.labels.to_bytes(1, 'big') + \
           rrsig_record.orig_ttl.to_bytes(4, 'big') + rrsig_record.expiration + \
           rrsig_record.inception + rrsig_record.tag.to_bytes(2, 'big') + \
           rrsig_record.signer_name

    for rr in rr_set:
        data += RRSignableData(rr, domain, rrsig_record.orig_ttl)

    return data


def createDSRecord(dnskey, domain):
    """
    A DS record is just the hash of a public key. Uses SHA256
    :param dnskey: The DNSKEY record
    :param domain: The domain name
    :return: The SHA256 hash of the DNSKEY record
    """
    data = formatName(domain)

    data += dnskey.rdata

    hasher = SHA256.new()
    hasher.update(data)
    return hasher.digest()


def formatName(name):
    """
    Puts a domain name into that form DNS loves so much
    :param name: A domain name string
    :return: The name formatting for verification use
    """
    name_bytes = bytearray(len(name) + 2)
    i = 0
    for domain in name.split('.'):
        name_bytes[i] = len(domain)
        i += 1
        insertBytes(name_bytes, domain.encode('utf-8', 'strict'), i)
        i += len(domain)
    name_bytes[i] = 0
    return name_bytes


def RRSignableData(rr, owner, orig_ttl):
    """
    This will take a RR and return the bytes to be used in signing
    # RFC on signiture calculation: https://tools.ietf.org/html/rfc4034#section-3.1

    owner is the domain owner (EX: 'example.com', 'com'). This TECHNICALLY should
    be in the rr, but we never figured out the pointer name storage thing
    :param rr: The Resource record
    :param owner: The owner of the RR
    :param orig_ttl: original TTL from RRSIG record
    :return: The data set for verification
    """
    formatted_owner = formatName(owner)
    return formatted_owner + rr.type.to_bytes(2, 'big') + rr.clazz.to_bytes(2, 'big') + \
           orig_ttl.to_bytes(4, 'big') + rr.rdata_len.to_bytes(2, 'big') + rr.rdata


def verify_signature(signature, key, recordset):
    """
    Verifies a signature
    :param signature:  The signature
    :param key: The key
    :param recordset: The recordset to verify
    :return: True if verified, false otherwise
    """
    expo, mod = get_expo_and_mod(key)
    constructed_key = RSA.construct((mod, expo))
    cipher = PKCS1_v1_5.new(constructed_key)
    return cipher.verify(SHA256.new(recordset), signature)


def get_expo_and_mod(dnskey):
    """
    Gets the exponent and modulus from a DNSKEY record
    :param dnskey: The DNSKEY record
    :return: Tuples of (exponent, modulus)
    """
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
