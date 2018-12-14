#!/usr/bin/python

from argparse import ArgumentParser
import sys
import time

from DNSPacket import DNSPacket
from network import UDPCommunication
import crypto
import util
from util import dprint

DEFAULT_PORT = 53


def getArgumentDict():
    ap = ArgumentParser()
    ap.add_argument('server', help='\"@server:port\" - address of the dns server')
    ap.add_argument('domain-name', help='Domain name to query for')
    ap.add_argument('record', help='Type of record you are requesting (A, DNSKEY, or DS)')
    ap.add_argument('--debug', help='Include printing for debugging', action='store_true')
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
        sys.exit(1)

    if args['debug']:
        util.debug_print_enabled = True

    connection = UDPCommunication()

    query_type = DNSPacket.RR_TYPE_A
    if record == "DNSKEY":
        query_type = DNSPacket.RR_TYPE_DNSKEY
    elif record == "DS":
        query_type = DNSPacket.RR_TYPE_DS

    split_domain = domain_name.split('.')
    parent_domain = '.'.join(split_domain[1:])


    # Regardless of query type, we need to verify the zone's public key first
    if not verifyZone(domain_name, connection, resolver_address):
        print("ERROR\tMISSING-DS")
        sys.exit(1)

    if query_type == DNSPacket.RR_TYPE_A:
        dprint("\n\n\nGetting A Record:")
        arecord_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_A)
        rr_set = get_rrset(arecord_response)
        rrsig_set = get_rrsigs(arecord_response)
        time.sleep(1)
        dnskey_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_DNSKEY)
        print("dnskey response:")
        dnskey_response.print()
        #dnskey_response.dump()
        keys = get_keys(dnskey_response)
        associated_rrsig = validate_A_record(keys, rrsig_set, rr_set, domain_name)
        if associated_rrsig is not None:
            # Print out the record info here
            print("Verified! print output is coming soon to a program near you")
        """ 
        valid = "INVALID"
        if verifyZone(domain_name, connection, resolver_address):
            valid = "VALID"
        for record in arecord_response.answers:
            if record.type != DNSPacket.RR_TYPE_RRSIG:
                dprint(record, associated_rrsig, valid)
        """

    if query_type == DNSPacket.RR_TYPE_DNSKEY:
        # TODO: This doesn't work at all fyi
        # TODO: also have to handle query_type = DS
        dprint("\n\n\nGetting Keys:")
        dnskey_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_DNSKEY)
        dprint("\nDNSKEY Record Response packet:")
        keys = get_keys(dnskey_response)
        # dnskey_response.dump()
        rrsig_set = get_rrsigs(arecord_response)

        # todo?
        rrset = keys

        associated_rrsig = validate_DNS_record(keys, rrsig_set, rr_set, domain_name)
        if associated_rrsig is not None:
            # Print out DNSKEY record info here
            print("Verified! print output is coming soon to a program near you")



def get_packet(connection, domain_name, resolver_address, type):
    query = DNSPacket.newQuery(domain_name, type, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    return connection.waitForPacket()


"""
Pulls DNSKEYs out of a response packet
"""
def get_keys(dnskey_response, error_if_empty=False):
    keys = []
    for answer in dnskey_response.answers:
        if answer.type == DNSPacket.RR_TYPE_DNSKEY:
            keys.append(answer)
    if error_if_empty == True  and  len(keys) == 0:
        print("ERROR\tMISSING-DNSKEY")
        sys.exit(1)
    return keys

"""
Pulls out the RRSIGs from a response packet
"""
def get_rrsigs(response, error_if_empty=False):
    rrsig_set = []
    for answer in response.answers:
        if answer.type == DNSPacket.RR_TYPE_RRSIG:
            rrsig_set.append(answer)
    return rrsig_set

"""
Pulls out the RRSET which was signed from a response packet
"""
def get_rrset(response, error_if_empty=False):
    rr_set = []
    for answer in response.answers:
        if answer.type != DNSPacket.RR_TYPE_RRSIG:
            rr_set.append(answer)
    return rr_set

def validate_A_record(keys, rrsig_set, rr_set, domain_name):
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
            dprint("ERROR\tUNKNOWN ALGORITHM", sig.algorithm)
            return False
        rrset_data = crypto.createRRSetHash(rr_set, sig, domain_name)
        for key in keys:
            if crypto.verify_signature(sig.signature, key, rrset_data):
                return sig
    return False


#####  TO DO:  ####
# This should validate the DNSKEY reponse we get by checking the RRset against the RRsig(s). Possibly this and the a set validation can just be done with 1 function? "validate_RRSET"
def validate_DNSKEY_record(keys, rr_set, domain_name, parent_domain):
    pass
    """
    #dprint("\n\n\nGetting DS record from {}".format(parent_domain))
    # Now, fetch DS record from parent zone:

    ds_records = rr_set
    for ds_record in ds_records:
        for key in keys:
            # dprint("Testing key {0} against DS record {1}".format(key, ds_record))
            ds_digest = ds_record.digest
            key_hashed = crypto.createDSRecord(key, domain_name)
            # dprint("\nDS hash: ", ds_digest)
            # dprint("DNSKEY hash:", key_hashed)
            if ds_digest == key_hashed:
                return True
    """


"""
Attempts to verify the public key of the given zone by establishing PKI from root
"""
def verifyZone(domain_name, connection, resolver_address):
    split_domain = domain_name.split('.')
    for i in range(len(split_domain)):
        cur_domain = '.'.join(split_domain[i:])
        parent_domain = '.'.join(split_domain[i+1:])
        dprint("\n\nVerifying {0} key using {1}".format(cur_domain, parent_domain))


        # Fetch DS records
        query = DNSPacket.newQuery(cur_domain, DNSPacket.RR_TYPE_DS, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        ds_response = connection.waitForPacket()
        #dprint("\nds record packet:")
        #ds_response.dump()

        # Pull DS records out from the response
        ds_records = []
        for answer in ds_response.answers:
            if answer.type == DNSPacket.RR_TYPE_DS:
                ds_records.append(answer)
        if len(ds_records) == 0:
            #print("MISSING-DS")
            return False
        dprint("\nFound {0} ds records".format(len(ds_records)))

        # Fetch DNSKEY records
        query = DNSPacket.newQuery(cur_domain, DNSPacket.RR_TYPE_DNSKEY, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        dnskey_response = connection.waitForPacket()
        #dprint("\ndnskey_response packet:")
        # dnskey_response.dump()

        # Pull keys from the response
        keys = []
        for answer in dnskey_response.answers:
            if answer.type == DNSPacket.RR_TYPE_DNSKEY:  # and  answer['sep'] == 1:
                keys.append(answer)
        if len(keys) == 0:
            #print("MISSING-DNSKEY")
            return False
        dprint("\nFound {0} keys".format(len(keys)))

        # Try to validate a key, any key
        key_validated = False
        for ds_record in ds_records:
            for key in keys:
                ds_digest = ds_record.digest
                key_hashed = crypto.createDSRecord(key, cur_domain)
                dprint("\nDS hash: ", ds_digest)
                dprint("DNSKEY hash:", key_hashed)
                if ds_digest == key_hashed:
                    dprint("MATCH WOOHOO")
                    key_validated = True
                    break
            if key_validated:
                break
        else:
            dprint("ERROR: Unable to validate any DNSKEY with parent zone")
            return False
    # We made it!
    return True



if __name__ == '__main__':
    main()
