#!/usr/bin/python3
"""
Project 4
Chris Grace (ctg2887)
Sam Hedin (sph3971)
"""
import itertools
import sys
from argparse import ArgumentParser

import crypto
import util
from DNSPacket import DNSPacket
from network import UDPCommunication
from records.Record import print_record
from util import dprint

DEFAULT_PORT = 53


def getArgumentDict():
    """
    Parses command line arguments
    :return: A dictionary containing the command line arguments
    """
    ap = ArgumentParser()
    ap.add_argument('server', help='\"@server:port\" - address of the dns server')
    ap.add_argument('domain-name', help='Domain name to query for')
    ap.add_argument('record', help='Type of record you are requesting (A, DNSKEY, or DS)')
    ap.add_argument('--debug', help='Include printing for debugging', action='store_true')
    args = ap.parse_args()
    # vars(..) will return the dict the namespace is using
    return vars(args)


def parse_server(addr):
    """
    Pasers the server information from the command line
    :param addr: The address string to parse
    :return: The resolver address as a tuple
    """
    if addr[0] != '@':
        print("ERROR\tServer must start with \"@\" symbol!")
        sys.exit(0)
    split_addr = addr.split(':')
    ip = split_addr[0][1:]
    port = split_addr[1] if len(split_addr) > 1 else DEFAULT_PORT
    return ip, port


def main():
    # Handle arguments
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

    # Regardless of query type, we need to verify the chain of trust
    if not verify_zone(domain_name, connection, resolver_address):
        print("ERROR\tMISSING-DS")
        sys.exit(1)

    if query_type == DNSPacket.RR_TYPE_A:
        dprint("\n\n\nGetting A Record:")
        arecord_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_A)
        arecord_response.print()
        arecord_response.dump()
        rr_set = get_rrset(arecord_response, error_if_empty="ERROR\tMISSING-A")
        rrsig_set = get_rrsigs(arecord_response, error_if_empty="ERROR\tMISSING-RRSIG")
        dnskey_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_DNSKEY)

        keys = get_keys(dnskey_response, error_if_empty="ERROR\tMISSING-DNSKEY")
        key_rrsig_set = get_rrsigs(arecord_response, error_if_empty="ERROR\tMISSING-RRSIG")
        if validate_RRSET(keys, key_rrsig_set, rr_set, domain_name) is None:
            print("ERROR\tINVALID-RRSIG")
            sys.exit(1)

        associated_rrsig = validate_RRSET(keys, rrsig_set, rr_set, domain_name)
        if associated_rrsig is not None:
            for record in rr_set:
                print_record(record, associated_rrsig, True)
        else:
            for record in rr_set:
                print_record(record, associated_rrsig, False)
            print("ERROR\tINVALID-RRSIG")
            sys.exit(1)

    elif query_type == DNSPacket.RR_TYPE_DNSKEY:
        dprint("\n\n\nGetting Keys:")
        dnskey_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_DNSKEY)
        dprint("\nDNSKEY Record Response packet:")
        dnskey_response.dump()
        keys = get_keys(dnskey_response, error_if_empty="ERROR\tMISSING-DNSKEY")
        rrsig_set = get_rrsigs(dnskey_response, error_if_empty="ERROR\tMISSING-RRSIG")
        rr_set = get_rrset(dnskey_response)

        associated_rrsig = validate_RRSET(keys, rrsig_set, rr_set, domain_name)
        if associated_rrsig is not None:
            for record in rr_set:
                print_record(record, associated_rrsig, True)
        else:
            for record in rr_set:
                print_record(record, associated_rrsig, False)
            print("ERROR\tINVALID-RRSIG")
            sys.exit(1)

    elif query_type == DNSPacket.RR_TYPE_DS:
        dprint("\n\n\nGetting DS records")
        ds_response = get_packet(connection, domain_name, resolver_address, DNSPacket.RR_TYPE_DS)
        ds_response.dump()
        ds_rr_set = get_rrset(ds_response, error_if_empty="ERROR\tMISSING-DS")
        ds_rrsig_set = get_rrsigs(ds_response, error_if_empty="ERROR\tMISSING-RRSIG")

        dnskey_response = get_packet(connection, parent_domain, resolver_address, DNSPacket.RR_TYPE_DNSKEY)
        dprint("\nDNSKEY Record Response packet:")
        keys = get_keys(dnskey_response, error_if_empty="ERROR\tMISSING-DNSKEY")

        associated_rrsig = validate_RRSET(keys, ds_rrsig_set, ds_rr_set, domain_name)
        for ds_record in ds_rr_set:
            if associated_rrsig is not None:
                print_record(ds_record, associated_rrsig, True)
            else:
                print_record(ds_record, associated_rrsig, False)


def get_packet(connection, domain_name, resolver_address, type):
    """
    Requests a packet from domain_name and returns it
    :param connection: A UDPConnection to use
    :param domain_name: The domain name to request
    :param resolver_address: The resolver addresss
    :param type: The type of packet being requested
    :return: The packet
    """
    query = DNSPacket.newQuery(domain_name, type, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    return connection.waitForPacket()


def get_keys(dnskey_response, error_if_empty="="):
    """
    Pulls DNSKEYs out of a response packet
    :param response: A DNS response
    :param error_if_empty: The error to print if no non RRSIG records are found
    :return: A list of DNSKEY records
    """
    keys = []
    for answer in dnskey_response.answers:
        if answer.type == DNSPacket.RR_TYPE_DNSKEY:
            keys.append(answer)
    if error_if_empty != "" and len(keys) == 0:
        print(error_if_empty)
        sys.exit(1)
    return keys


def get_rrsigs(response, error_if_empty=""):
    """
    Pulls out the RRSIGs from a response packet
    :param response: A DNS response
    :param error_if_empty: The error to print if no non RRSIG records are found
    :return: A list of RRSIG records
    """
    rrsig_set = []
    for answer in response.answers:
        if answer.type == DNSPacket.RR_TYPE_RRSIG:
            rrsig_set.append(answer)
    if error_if_empty != "" and len(rrsig_set) == 0:
        print(error_if_empty)
        sys.exit(1)
    return rrsig_set


def get_rrset(response, error_if_empty=""):
    """
    Pulls out the RRSET which was signed from a response packet
    :param response: A DNS response
    :param error_if_empty: The error to print if no non RRSIG records are found
    :return: The RRSET
    """
    rr_set = []
    for answer in response.answers:
        if answer.type != DNSPacket.RR_TYPE_RRSIG:
            rr_set.append(answer)
    if error_if_empty != "" and len(rr_set) == 0:
        print(error_if_empty)
        sys.exit(1)
    return rr_set


def validate_RRSET(keys, rrsig_set, rr_set, domain_name):
    """
    Validates the signature on an RRset
    :param keys: The DNSKEYS to check with
    :param rrsig_set: A set of RRSIGs to check
    :param rr_set: The RRset
    :param domain_name: The domain name of the RRset
    :return: The RRSIG record that verified
    """
    for sig in rrsig_set:
        if sig.algorithm != DNSPacket.ALGO_TYPE_RSASHA256:
            dprint("ERROR\tUNKNOWN ALGORITHM", sig.algorithm)
            return None
        for set_ordering in itertools.permutations(rr_set, len(rr_set)):
            rrset_data = crypto.createRRSetData(set_ordering, sig, domain_name)
            for key in keys:
                if crypto.verify_signature(sig.signature, key, rrset_data):
                    return sig
    return None


def verify_zone(domain_name, connection, resolver_address):
    """
    Attempts to verify the public key of the given zone by establishing PKI from root
    :param domain_name: The domain name to begin at
    :param connection: A UDP connection object to use
    :param resolver_address: The address of the resolver
    :return: True if zone verified, false otherwise
    """
    split_domain = domain_name.split('.')
    for i in range(len(split_domain)):
        cur_domain = '.'.join(split_domain[i:])
        parent_domain = '.'.join(split_domain[i + 1:])
        dprint("\n\nVerifying {0} key using {1}".format(cur_domain, parent_domain))

        # Fetch DS records
        query = DNSPacket.newQuery(cur_domain, DNSPacket.RR_TYPE_DS, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        ds_response = connection.waitForPacket()

        # Pull DS records out from the response
        ds_records = []
        for answer in ds_response.answers:
            if answer.type == DNSPacket.RR_TYPE_DS:
                ds_records.append(answer)
        if len(ds_records) == 0:
            return False
        dprint("\nFound {0} ds records".format(len(ds_records)))

        # Fetch DNSKEY records
        query = DNSPacket.newQuery(cur_domain, DNSPacket.RR_TYPE_DNSKEY, using_dnssec=True)
        connection.sendPacket(resolver_address, query)
        dnskey_response = connection.waitForPacket()

        # Pull keys from the response
        keys = get_keys(dnskey_response)
        if len(keys) == 0:
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
    return True


if __name__ == '__main__':
    main()
