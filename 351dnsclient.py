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

    print("Trying DNSSEC:")
    query = DNSPacket.newQuery(domain_name, query_type, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    print("")
    response_packet = connection.waitForPacket()
    print("\nResponse packet:")
    response_packet.dump()


if __name__ == '__main__':
    main()
