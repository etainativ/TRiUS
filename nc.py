#!/home/dn/venv/bin/python
import ipaddress
import socket
import struct
import threading
import sys
import argparse



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--listen", action="store_true", help="listen")
    parser.add_argument("ip")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    address = ((args.ip, args.port))

    sock_type = socket.AddressFamily.AF_INET
    if ipaddress.ip_address(args.ip).version == 6:
        sock_type = socket.AddressFamily.AF_INET6

    s = socket.socket(family=sock_type)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    if args.listen:
        s.bind(address)
        s.listen()
        sock = s.accept()[0]

    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 179)
        s.connect(address)
        sock = s

    def recv(sock_):
        while True:
            print(sock_.recv(64).decode().strip())

    threading.Thread(target=recv, args=(sock,)).start()

    try:
        while True:
            ans = sys.stdin.readline()
            sock.send(ans.encode())
    except:
        sock.close()
        s.close()
