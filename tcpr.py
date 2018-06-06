from gevent.monkey import patch_all; patch_all()

import gevent
import gevent.socket
import socket
import signal
import sys
from scapy.all import TCP, IP, conf, L3RawSocket, send
from netfilterqueue import NetfilterQueue, Packet
from connection import Connection, get_connection, get_old_connection, send_local, pp, connections, _accept, _drop


pudb_active = False
def pudb():
    global pudb_active
    if not pudb_active:
        pudb_active = True
        from pudb import set_trace
        set_trace()
        pudb_active = False

conf.L3socket = L3RawSocket
conf.verb = 0
nf_queues = []
sockets = []
def sigkill(sig, frame):
    for nfqueue in nf_queues:
        nfqueue.unbind()

    for socket in sockets:
        socket.close()

    print("closing")
    sys.exit(0)


signal.signal(signal.SIGINT, sigkill)

FIN=0x01
SYN=0x02
RST=0x04
PSH=0x08
ACK=0x10
URG=0x20
ECE=0x40
CWR=0x80


def update_tcp(ip, con, is_application, pkt):
    tcp = ip[1]
    if is_application:
        con.remote_seq = tcp.ack
        tcp.seq -= con.delta
        tcp.sport = con.initial_local_port

    else:
        con.local_seq = tcp.ack
        tcp.ack += con.delta
        tcp.dport = con.local_port

    del(tcp.chksum)
    pp("Adter update:", ip)
    rebuild_pkt(pkt, ip)

def rebuild_pkt(pkt, ip):
    pkt.set_payload(ip.build())


def create_nfqueue_thread(nfqueue_id, func):
    nfqueue = NetfilterQueue()
    nfqueue.bind(nfqueue_id, func)
    nf_queues.append(nfqueue)
    s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    sockets.append(s)
    return gevent.spawn(nfqueue.run_socket, s)


def tcpr_application(pkt):
    ip = IP(pkt.get_payload())
    tcp = ip.getlayer(TCP)
    pp("Application:", ip)
    con = get_connection(ip.src, ip.dst, tcp.sport, tcp.dport)

    # existing connection
    if con is not None: 
        if FIN & tcp.flags:
            print("Application trying to exit")

            #injecting FIN back to close the tcp gracefully
            con.con_down = True
            con.end_fin()
            return _drop(pkt)

        if RST & tcp.flags:
            con.con_down = True
            return _drop(pkt)

        if con.con_down:
            if SYN & tcp.flags and ACK & tcp.flags:
                con.recover_ack(tcp)
            return _drop(pkt)

    # new connection
    else:
        # first packat must be SYN
        if not SYN & tcp.flags:
            print("Non syn first packet !!!")
            return _accept(pkt)

        con = get_old_connection(ip.src, ip.dst, tcp.sport)
        
        # recovery for connect (port switched)
        if con is not None:
            if not SYN & tcp.flags:
                print("Warning Known SEQUENCE, port changed without syn")
                return _drop(pkt)


        # new connection (should be SYN + ACK)
        con = Connection(ip.src, ip.dst, tcp.sport, tcp.dport, True) 
        pp("new Connection:", ip)
        con.register()
        print("Recovery")


    update_tcp(ip, con, True, pkt)
    return _accept(pkt)


def tcpr_peer(pkt):
    ip = IP(pkt.get_payload())
    tcp = ip[1]
    pp("Peer:", ip)
    con = get_connection(ip.dst, ip.src, tcp.dport, tcp.sport)
    if con is not None:
        if tcp.flags & SYN:
            # first contact
            return _accept(pkt)

        if con.con_down:
            # check if fin sent
            if tcp.flags & FIN and tcp.flags & ACK:
                return _accept(pkt)
            # reconnect sequence final ACK
            if tcp.flags == ACK:
                con.con_down = False
                return _accept(pkt)
            return _drop(pkt)

        update_tcp(ip, con, False, pkt)
    return _accept(pkt)


def keypress():
    while True:
        gevent.socket.wait_read(sys.stdin.fileno())
        msg = sys.stdin.readline()
        if msg.strip() == "r": 
            print("Recovering")
            for connection in connections:
                connection.recover_syn()


if __name__ == "__main__":
    app_thread = create_nfqueue_thread(0, tcpr_application)
    peer_thread = create_nfqueue_thread(1, tcpr_peer)
    input_thread = gevent.spawn(keypress)

    gevent.joinall([app_thread, peer_thread])
