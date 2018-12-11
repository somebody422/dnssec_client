"""

The hashing and sha stuff

"""

from util import insertBytes
import struct

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

owner is the domain owner (EX: 'example.com', 'com'). This TECHNICALLY should
be in the rr, but we never figured out the pointer name storage thing
"""
def RRSignableData(rr, owner):
	formatted_owner = formatName(owner)
	return struct.pack("{0}sHHIH{1}s ".format(len(formatted_owner), rr['rdata_len']), formatted_owner ,rr['type'], rr['class'], rr['ttl'], rr['rdata_len'], rr['rdata'])



