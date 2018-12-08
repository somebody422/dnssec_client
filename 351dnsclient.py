#!/usr/bin/python

from argparse import ArgumentParser
import sys
from DNSPacket import DNSPacket
from network import UDPCommunication

DEFAULT_PORT = 53


def getArgumentDict():
    ap = ArgumentParser()

    ap.add_argument('-ns', action='store_true')
    ap.add_argument('-mx', action='store_true')
    ap.add_argument('address', help='\"@server:port\" - address of the dns server')
    ap.add_argument('name', help='Name to query for')
    args = ap.parse_args()
    # vars(..) will return the dict the namespace is using
    return vars(args)


def main():
    args = getArgumentDict()
    domain = args['name']
    # Parse out server
    addr = args['address']
    if addr[0] != '@':
        print("ERROR\tAddress must start with \"@\" symbol!")
        sys.exit(0)
    split_addr = addr.split(':')
    ip = split_addr[0][1:]
    port = split_addr[1] if len(split_addr) > 1 else DEFAULT_PORT
    resolver_address = (ip, port)

    connection = UDPCommunication()

    # Note that while multiple questions in 1 packet is TECHNICALLY supported, it is not the norm and should be avoided. We will build a different packet for each query
    query = DNSPacket.newQuery(domain, DNSPacket.RR_TYPE_A, using_dnssec=False)
    connection.sendPacket(resolver_address, query)
    #connection.listen()
    # On error, this will exit the program
    response_packet = connection.waitForPacket()
    print("Response packet:")
    response_packet.dump()

    print("\n\nTrying DNSSEC:")
    query = DNSPacket.newQuery(domain, DNSPacket.RR_TYPE_DNSKEY, using_dnssec=True)
    connection.sendPacket(resolver_address, query)
    response_packet = connection.waitForPacket();
    print("Response packet:")
    response_packet.dump()



if __name__ == '__main__':
    main()
