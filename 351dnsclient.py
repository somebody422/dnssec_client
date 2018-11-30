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

    # Parse out server
    addr = args['address']
    if addr[0] != '@':
        print("ERROR\tAddress must start with \"@\" symbol!")
        sys.exit(0)
    split_addr = addr.split(':')
    ip = split_addr[0][1:]
    port = split_addr[1] if len(split_addr) > 1 else DEFAULT_PORT
    address = (ip, port)

    connection = UDPCommunication()
    query = DNSPacket.newQuery(args['name'], DNSPacket.TYPE_A)
    connection.sendPacket(address, query.bytes)
    connection.listen()


if __name__ == '__main__':
    main()
