#!/usr/bin/python

from argparse import ArgumentParser
import sys
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


    # todo: move crypto stuff into its own file at some point
    print('\n\n\nValidating the A RRSET:')
    rr_set = []
    arecord_sig = None
    for answer in arecord_response.answers:
        if answer['type'] == DNSPacket.RR_TYPE_A:
            rr_set.append(answer)
        elif answer['type'] == DNSPacket.RR_TYPE_RRSIG:
            arecord_sig = answer
    if len(rr_set) == 0  or  arecord_sig == None:
        print("ERROR: Unable to find A records and signiture")
        sys.exit(1)

    ## ==== TO DO: The RRset needs to be sorted into canonical order. May get the wrong answer otherwise. That should just mean calling sort with the right arguments here
    # https://tools.ietf.org/html/rfc4034#section-3.1.8.1
    # https://tools.ietf.org/html/rfc4034#section-3.1.8.1

    #print("rr_set:", rr_set)
    #print("arecord_sig:", arecord_sig)

    keys = []
    for answer in dnskey_response.answers:
        if answer['type'] == DNSPacket.RR_TYPE_DNSKEY:  #and  answer['sep'] == 1:
            keys.append(answer)
    if len(keys) == 0:
        print("ERROR Cannot find any keys")
        sys.exit(1)
    #print("keys:", keys)

    # RFC on signiture calculation: https://tools.ietf.org/html/rfc4034#section-3.1
    a = crypto.RRSignableData(rr_set[0], 'verisignlabs.com')
    import pdb; pdb.set_trace()



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
    """


if __name__ == '__main__':
    main()
