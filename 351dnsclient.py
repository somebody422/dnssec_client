#!/usr/bin/python

from argparse import ArgumentParser
import sys
from DNSPacket import DNSPacket
from network import UDPCommunication

DEFAULT_PORT = 53


def getArgumentDict():
    ap = ArgumentParser()
    ap.add_argument('server', help='\"@server:port\" - address of the dns server')
    ap.add_argument('domain-name', help='Domain name to query for')
    ap.add_argument('record', help='Type of record you are requesting (A, DNSKEY, or DS)')
    args = ap.parse_args()
    # vars(..) will return the dict the namespace is using
    return vars(args)


def main():
    args = getArgumentDict()
    domain_name = args['domain-name']

    # Parse out server
    addr = args['server']
    if addr[0] != '@':
        print("ERROR\tServer must start with \"@\" symbol!")
        sys.exit(0)
    split_addr = addr.split(':')
    ip = split_addr[0][1:]
    port = split_addr[1] if len(split_addr) > 1 else DEFAULT_PORT
    resolver_address = (ip, port)

    record = args['record']
    if record not in ["A", "DNSKEY", "DS"]:
        print("ERROR\t" + str(record) + " not supported")

    connection = UDPCommunication()

    query_type = DNSPacket.RR_TYPE_A
    if record == "DNSKEY":
        query_type = DNSPacket.RR_TYPE_DNSKEY
    elif record == "DS":
        query_type = DNSPacket.RR_TYPE_DS

    # Note that while multiple questions in 1 packet is TECHNICALLY supported, it is not the norm and should be
    # avoided. We will build a different packet for each query
    # query = DNSPacket.newQuery(domain_name, query_type, using_dnssec=False)
    # connection.sendPacket(resolver_address, query)
    #
    # # On error, this will exit the program
    # response_packet = connection.waitForPacket()
    # print("\nResponse packet:")
    # response_packet.dump()


    # Testing verifying an A record: ignoring the query type setting for now  -sam
    print("\n\n\nGetting A Record:")
    query = DNSPacket.newQuery(domain_name, DNSPacket.RR_TYPE_A, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    arecord_response = connection.waitForPacket()
    print("\narecord_response packet:")
    #arecord_response.dump()

    print("\n\n\nGetting Key:")
    query = DNSPacket.newQuery(domain_name, DNSPacket.RR_TYPE_DNSKEY, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    dnskey_response = connection.waitForPacket()
    print("\ndnskey_response packet:")
    #dnskey_response.dump()

    # If DNSSEC D0 bit is enabled, the A record fetch will get its RRSIG as well. So manually fetching RRSIGs is unnecessary
    """
    print("\n\n\nGetting RRSIG:")
    query = DNSPacket.newQuery(domain_name, DNSPacket.RR_TYPE_RRSIG, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    rrsig_response = connection.waitForPacket()
    print("\nrrsig_response packet:")
    rrsig_response.dump()
    """

    # Now, fetch DS record from parent zone:
    split_domain = domain_name.split('.')
    parent_domain = '.'.join(split_domain[1:])
    print("\n\n\nGetting DS record from {}".format(parent_domain))
    query = DNSPacket.newQuery(domain_name, DNSPacket.RR_TYPE_DS, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    ds_response = connection.waitForPacket()
    print("\narecord_response packet:")
    ds_response.dump()


if __name__ == '__main__':
    main()
