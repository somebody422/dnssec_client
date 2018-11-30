"""
A file for networking functions

We will be using UDP to send and receive packets.

"""

import socket
import select
from DNSPacket import DNSPacket
from util import dump_packet



class UDPCommunication:
    # UDP_PORT = 5005
    TIMEOUT = 5

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))
        self.port = self.sock.getsockname()[1]

    def sendPacket(self, addr, data):
        self.addr = addr
        self.data = data
        print("Query Packet:")
        dump_packet(data)
        self.sock.sendto(data, addr)

    def listen(self):
        packet_id = 1
        num_tries = 0
        while True:
            # print("Listening..")
            ready = select.select([self.sock], [], [], UDPCommunication.TIMEOUT)
            if ready[0]:
                data, addr = self.sock.recvfrom(1024)  # buffer size is 1024 bytes
                print("\nResponse Packet:")
                dump_packet(data)
                packet = DNSPacket.newFromBytes(data, packet_id)
                # TODO: increment packet_id or no?
                if not packet:
                    print("Response Corrupted, retrying...")
                    self.sendPacket(self.addr, self.data)
                    num_tries += 1
                    if num_tries >= 3:
                        print("Max tries reached")
                        break
                elif not packet.tc:
                    break
            else:
                print("NORESPONSE")
                exit(0)
