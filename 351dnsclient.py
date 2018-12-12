#!/usr/bin/python

from argparse import ArgumentParser
import sys
import time

from DNSPacket import DNSPacket
from network import UDPCommunication
import crypto

DEFAULT_PORT = 53


def getArgumentDict():
    ap = ArgumentParser()
    ap.add_argument('server', help='\"@server:port\" - address of the dns server')
    ap.add_argument('domain-name', help='Domain name to query for')
    ap.add_argument('record', help='Type of record you are requesting (A, DNSKEY, or DS)')
    args = ap.parse_args()
    # vars(..) will return the dict the namespace is using
    return vars(args)


def parse_server(addr):
    if addr[0] != '@':
        print("ERROR\tServer must start with \"@\" symbol!")
        sys.exit(0)
    split_addr = addr.split(':')
    ip = split_addr[0][1:]
    port = split_addr[1] if len(split_addr) > 1 else DEFAULT_PORT
    return ip, port


def main():
    args = getArgumentDict()
    domain_name = args['domain-name']

    resolver_address = parse_server(args['server'])

    record = args['record']
    if record not in ["A", "DNSKEY", "DS"]:
        print("ERROR\t" + str(record) + " NOT SUPPORTED")

    connection = UDPCommunication()

    query_type = DNSPacket.RR_TYPE_A
    if record == "DNSKEY":
        query_type = DNSPacket.RR_TYPE_DNSKEY
    elif record == "DS":
        query_type = DNSPacket.RR_TYPE_DS

    split_domain = domain_name.split('.')
    parent_domain = '.'.join(split_domain[1:])

    if query_type == DNSPacket.RR_TYPE_A:
        print("\n\n\nGetting A Record:")
        arecord_response = get_record(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_A)
        rr_set = get_rrset(arecord_response)
        rrsig_set = get_rrsigs(arecord_response)
        time.sleep(1)
        dnskey_response = get_record(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_DNSKEY)
        keys = get_keys(dnskey_response)
        associated_rrsig = get_rrsig_for_a_record(keys, rrsig_set, rr_set, domain_name)
        valid = "INVALID"
        if verifyZone(domain_name, connection, resolver_address):
            valid = "VALID"
        for record in arecord_response.answers:
            if record.type != DNSPacket.RR_TYPE_RRSIG:
                print(record, associated_rrsig, valid)
    if query_type == DNSPacket.RR_TYPE_DNSKEY:
        # TODO: This doesn't work at all fyi
        # TODO: also have to handle query_type = DS
        print("\n\n\nGetting Keys:")
        query = DNSPacket.newQuery(domain_name, DNSPacket.RR_TYPE_DNSKEY, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        dnskey_response = connection.waitForPacket()
        print("\nDNSKEY Record Response packet:")
        keys = get_keys(dnskey_response)
        # dnskey_response.dump()
        rrsig_set = get_rrsigs(arecord_response)
        print("A Record valid:", get_rrsig_for_a_record(keys, rrsig_set, rr_set, domain_name))

        query = DNSPacket.newQuery(domain_name, DNSPacket.RR_TYPE_DS, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        ds_response = connection.waitForPacket()
        print("\nDS record response packet:")
        # ds_response.dump()

        rr_set = get_rrset(ds_response)
        print("DNSKEY valid", validate_DNSKEY_record(keys, rr_set, domain_name, parent_domain))


def validate_response(response, connection, domain_name, parent_domain, resolver_addr):
    if response.answers[0].type == DNSPacket.RR_TYPE_A:
        dnskey_response = get_record(connection, domain_name, resolver_addr, DNSPacket.RR_TYPE_DNSKEY)
        keys = get_keys(dnskey_response)
        rr_set = get_rrset(response)
        rrsig_set = get_rrsigs(response)
        if get_rrsig_for_a_record(keys, rrsig_set, rr_set, domain_name):
            validate_response(dnskey_response, connection, domain_name, resolver_addr)
        else:
            print("ERROR\tA Record invalid")
    elif response.answers[0].type == DNSPacket.RR_TYPE_DNSKEY:
        ds_response = get_record(connection, domain_name, resolver_addr, DNSPacket.RR_TYPE_DS)
        keys = get_keys(response)
        rr_set = get_rrset(ds_response)
        if validate_DNSKEY_record(keys, rr_set, domain_name, parent_domain):
            validate_DNSKEY_record(keys, rr_set, domain_name, parent_domain)
        else:
            print("ERROR\tDNSKEY Record invalid")
    elif response.answers[0].type == DNSPacket.RR_TYPE_DS and parent_domain is not None:
        print("Not sure what to do here")



def get_record(connection, domain_name, resolver_address, type):
    query = DNSPacket.newQuery(domain_name, type, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    return connection.waitForPacket()

def get_keys(dnskey_response):
    keys = []
    for answer in dnskey_response.answers:
        if answer.type == DNSPacket.RR_TYPE_DNSKEY:  # and  answer['sep'] == 1:
            keys.append(answer)
    if len(keys) == 0:
        print("ERROR Cannot find any keys")
        sys.exit(1)
    return keys

def get_rrsigs(response):
    rrsig_set = []
    for answer in response.answers:
        if answer.type == DNSPacket.RR_TYPE_RRSIG:
            rrsig_set.append(answer)
    return rrsig_set

def get_rrset(response):
    rr_set = []
    for answer in response.answers:
        if answer.type != DNSPacket.RR_TYPE_RRSIG:
            rr_set.append(answer)
    return rr_set

def get_rrsig_for_a_record(keys, rrsig_set, rr_set, domain_name):
    ## ==== TO DO: The RRset needs to be sorted into canonical order. May get the wrong answer otherwise. That should just mean calling sort with the right arguments here
    # https://tools.ietf.org/html/rfc4034#section-3.1.8.1
    # https://tools.ietf.org/html/rfc4034#section-3.1.8.1
    """ THIS DOESN'T WORK because pretty much all the domains are using the pointer format. Need to figure that out first
    # Mucks the domain string to make alphabetic sort put things in canonical order
    def canonicalSorter(rr):
        domain = rr.name
        reversed_split_domain = reversed(domain.split('.'))
        # merge it into a single string
        "".join(reversed_split_domain)

    rr_set.sort(key = canonicalSorter)
    """
    # todo: handle more algorithms
    for sig in rrsig_set:
        if sig.algorithm != DNSPacket.ALGO_TYPE_RSASHA256:
            print("ERROR\tUNKNOWN ALGORITHM", sig.algorithm)
            sys.exit(1)
        rrset_data = crypto.createRRSetHash(rr_set, sig, domain_name)
        for key in keys:
            if crypto.verify_signature(sig.signature, key, rrset_data):
                return sig
    return False

def validate_DNSKEY_record(keys, rr_set, domain_name, parent_domain):
    print("\n\n\nGetting DS record from {}".format(parent_domain))
    # Now, fetch DS record from parent zone:

    ds_records = rr_set
    for ds_record in ds_records:
        for key in keys:
            # print("Testing key {0} against DS record {1}".format(key, ds_record))
            ds_digest = ds_record.digest
            key_hashed = crypto.createDSRecord(key, domain_name)
            # print("\nDS hash: ", ds_digest)
            # print("DNSKEY hash:", key_hashed)
            if ds_digest == key_hashed:
                return True
"""
Attempts to verify the public key of the given zone by establishing PKI from root
"""
def verifyZone(domain_name, connection, resolver_address):
    split_domain = domain_name.split('.')
    for i in range(len(split_domain)):
        cur_domain = '.'.join(split_domain[i:])
        parent_domain = '.'.join(split_domain[i+1:])
        print("\n\nVerifying {0} key using {1}".format(cur_domain, parent_domain))


        # Fetch DS records
        query = DNSPacket.newQuery(cur_domain, DNSPacket.RR_TYPE_DS, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        ds_response = connection.waitForPacket()
        #print("\nds record packet:")
        #ds_response.dump()

        # Pull DS records out from the response
        ds_records = []
        for answer in ds_response.answers:
            if answer.type == DNSPacket.RR_TYPE_DS:
                ds_records.append(answer)
        if len(ds_records) == 0:
            print("ERROR: Received no DS records")
            return False
        print("\nFound {0} ds records".format(len(ds_records)))

        # Fetch DNSKEY records
        query = DNSPacket.newQuery(cur_domain, DNSPacket.RR_TYPE_DNSKEY, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        dnskey_response = connection.waitForPacket()
        #print("\ndnskey_response packet:")
        # dnskey_response.dump()

        # Pull keys from the response
        keys = []
        for answer in dnskey_response.answers:
            if answer.type == DNSPacket.RR_TYPE_DNSKEY:  # and  answer['sep'] == 1:
                keys.append(answer)
        if len(keys) == 0:
            print("ERROR: Received no keys")
            return False
        print("\nFound {0} keys".format(len(keys)))

        # Try to validate a key, any key
        key_validated = False
        for ds_record in ds_records:
            for key in keys:
                ds_digest = ds_record.digest
                key_hashed = crypto.createDSRecord(key, cur_domain)
                print("\nDS hash: ", ds_digest)
                print("DNSKEY hash:", key_hashed)
                if ds_digest == key_hashed:
                    print("MATCH WOOHOO")
                    key_validated = True
                    break
            if key_validated:
                break
        else:
            print("ERROR: Unable to validate any DNSKEY with parent zone")
            return False
    # We made it!
    return True



if __name__ == '__main__':
    main()
