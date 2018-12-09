"""
Small utility functions which don't have a home :(

"""


# Replaces values in bytearray with values from bytes, starting at index
def insertBytes(ba, b, index):
    for i in range(index, min(len(ba), len(b) + index)):
        ba[i] = b[i - index]


def bytes_to_str(data):
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
