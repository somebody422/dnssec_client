"""
Small utility functions which don't have a home :(

"""

from datetime import datetime
import struct

# A global variable, which can be set from main
debug_print_enabled = False


def dprint(*args):
    if debug_print_enabled:
        print(*args)


def insertBytes(ba, b, index):
    """
    Inserts bytes into a bytearray
    :param ba: byte array
    :param b: bytes
    :param index: index to start at
    :return: None
    """
    for i in range(index, min(len(ba), len(b) + index)):
        ba[i] = b[i - index]


def bytes_to_str(data):
    """
    Converts bytes to a string with .'s at non lowercase letter characters
    :param data: The bytes
    :return: The string
    """
    s = ""
    for bit in data:
        if chr(bit) < ' ' or bit >= 127:
            s += '.'
        else:
            s += chr(bit)
    return s


# Prints a hex dump of the data to stdout
def dump_packet(data):
    """
    Dumps the contents of packet similar to how xxd looks
    :param data: The data to dump
    :return: None
    """
    count = 0
    for byte in data:
        if count % 16 == 0:
            print('{:04b}'.format(count // 8), end=" ")
        count += 1
        print('{:02x}'.format(byte), end=" ")
        if count % 8 == 0:
            print("\t", end="")
        if count == len(data):
            if count % 16 < 8:
                print(8 * "   " + "\t", end="")
            print((8 - count % 8) * "   " + "\t", end="")
        if count % 16 == 0 or count == len(data):
            s = ""
            for b in data[count - 16: count]:
                if chr(b) < ' ' or b >= 127:
                    s += '.'
                else:
                    s += chr(b)
            print(s)


def skip_name(bytes):
    """
    Returns the length of a name from a DNS record
    :param bytes: The bytes of the DNS record starting at the name
    :return: The number of bytes to skip
    """
    i = 0
    if (bytes[i] >> 6) == 0b11:
        # If the first two bits of the 'name' field are 1, then there is a pointer here, not the actual name.
        #  just move past it
        # print("Found a pointer to name")
        i += 2
    else:
        # Not a pointer.. move i past this string
        num_bytes = bytes[i]
        while num_bytes != 0:
            i += 1 + num_bytes
            num_bytes = bytes[i]
        i += 1
    return i


def parse_name(bytes):
    """
    Parses a name in a DNS record
    :param bytes: The bytes of the record starting at the name
    :return: A tuple containing the length of the name and the name
    """
    i = 0
    if (bytes[i] >> 6) == 0b11:
        # Name is stored as a 2-byte pointer. We will just ignore this for now
        domain = bytes[i:i + 2]
        i += 2
    else:
        # Not a pointer.. parse out the string
        reading_domain_string = True
        domain = []
        while reading_domain_string:
            num_bytes = bytes[i]
            # print("num_bytes =", num_bytes)
            domain.append(num_bytes.to_bytes(1, byteorder='big'))
            i += 1
            if num_bytes == 0:
                # A zero byte means the domain part is done
                # print("Done reading domain")
                reading_domain_string = False
            else:
                domain.append(bytes[i: i + num_bytes])
                i += num_bytes

    return i, domain


def ts_to_dt(ts):
    # timestamp to datetime
    return datetime.fromtimestamp(struct.unpack("!I", ts)[0])
