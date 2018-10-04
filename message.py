from enum import Enum

"""
Modulo para constantes simbolicas y funciones de construccion de mensajes.
"""

# Header constants
NCONNECT = 0x00  # Solicita conectarse a la red, se responde con PEERS
PCONNECT = 0x01  # Conecta con peers individualmente después de de NCONNECT
PEERS = 0x02
GETFILE = 0x03
SENDFILE = 0x04
DISCONNECT = 0x05
ADDME = 0x06
ADDTHIS = 0x07
REQDIR = 0x08  # Manda a preguntar por las carpetas locales de cada nodo
GIVEDIR = 0x09

# Mensajes de conexion constantes
NCONNMSG = b"\x00\xa5\xa5\xa5\xa5"
PCONNMSG = b"\x01\xa5\xa5\xa5\xa5"
DISCONNMSG = b"\x05\xa5\xa5\xa5\xa5"
PROCMSG = b"\x06\xa5\xa5\xa5\xa5"
REQDIRMSG = b"\x08\xa5\xa5\xa5\xa5"


def build_peers_message(plist):
    buff = bytearray()
    buff.append(PEERS)
    buff.extend(int.to_bytes(len(plist) * 6,
                             length=4, byteorder="big"))

    for pi in plist:
        buff.extend(ip_to_octets_iter(pi[0]))
        buff.extend(int.to_bytes(int(pi[1]), length=2, byteorder="big"))

    return buff


def build_addme_message(port):
    buff = bytearray()
    buff.append(ADDME)
    buff.extend(int.to_bytes(port, length=2, byteorder="big"))

    return buff


def build_addthis_message(pname, pport):
    buff = bytearray()
    buff.append(ADDTHIS)
    buff.extend(ip_to_octets_iter(pname))
    buff.extend(int.to_bytes(pport, length=2, byteorder="big"))

    return buff


def build_givedir_message(port, files):
    buff = bytearray(5)
    buff[0] = GIVEDIR
    buff.extend(int.to_bytes(port, length=2, byteorder="big"))


    if files:
        size = 2
        for f in files:
            namebytes = f.encode()
            buff.append(len(namebytes))
            buff.extend(namebytes)

            size += (len(namebytes) + 1)

        buff[1:5] = int.to_bytes(size, length=4, byteorder="big")
    else:
        buff.append(0x00)
        buff[1:5] = int.to_bytes(3, length=4, byteorder="big")

    return buff


def ip_to_octets_iter(ip):
    for octet in ip.split('.'):
        yield int(octet)


def octets_to_ip_iter(buff):
    for octet in buff:
        yield str(octet)


def parse_ip_bytes(buff):
    ips = []

    pos = 0
    end = 6
    pbytes = buff[pos:end]

    while pbytes:
        ips.append(
            [
                '.'.join(octets_to_ip_iter(pbytes[:4])),
                int.from_bytes(pbytes[4:], byteorder="big")
            ]
        )

        pos += 6
        end += 6
        pbytes = buff[pos:end]

    return ips

def parse_file_bytes(buff, bsize):
    port = int.from_bytes(buff[:2], byteorder="big")

    files = []

    pos = 2
    while pos < bsize:
        nfsize = buff[pos]
        nf = buff[pos + 1: pos + 1 + nfsize]

        print("TAM", nfsize, "NOM", nf)

        pos += nfsize + 1


    # while nfsize:
    #     print("\tTAM", nfsize, "ARCHIVO:", nf)
    #
    #     pos += nfsize
    #     nfsize = buff[pos]

if __name__ == '__main__':
    # p = ["192.168.0.1:9090", "255.255.255.255:1"]
    # p = [['127.0.0.1', '8888'], ['127.0.0.1', '8889'], ['192.168.0.1', '1111']]
    #
    # print([i for i in ip_to_octets_iter("192.168.0.1")])
    # print([i for i in ip_to_octets_iter("255.255.255.255")])
    # a = build_peers_message(p)
    #
    # print(a)
    # print(parse_ip_bytes(a[5:]))
    # print(build_addthis_message("192.168.0.1", 8081))

    print(build_givedir_message(['neon_palm_aesthetic.jpg', 'dummy.mp4']))
