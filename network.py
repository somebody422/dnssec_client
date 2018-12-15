"""
A file for networking functions

We will be using UDP to send and receive packets.
"""

import socket
import select
from DNSPacket import DNSPacket


class UDPCommunication:
    TIMEOUT = 5

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))
        self.port = self.sock.getsockname()[1]

    def sendPacket(self, addr, packet):
        """
        Sends a packet to addr
        :param addr: The address to send to
        :param packet: The packet to send
        :return: None
        """
        self.addr = addr
        self.data = packet.bytes
        self.sock.sendto(self.data, addr)

    def waitForPacket(self):
        """
        Waits for a response and returns the packet
        :return: The packet
        """
        packet_id = 1
        num_tries = 0
        while True:
            ready = select.select([self.sock], [], [], UDPCommunication.TIMEOUT)
            if ready[0]:
                data, addr = self.sock.recvfrom(4096)
                packet = DNSPacket.newFromBytes(data, packet_id)
                if not packet:
                    print("Response Corrupted, retrying...")
                    self.sock.sendto(self.data, self.addr)
                    num_tries += 1
                    if num_tries >= 3:
                        print("Max tries reached")
                        exit(0)
                elif packet.tc:
                    print("ERROR: Packet was truncated")
                    break
                else:
                    return packet
            else:
                print("NORESPONSE")
                exit(1)

