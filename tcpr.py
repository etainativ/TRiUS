from gevent.monkey import patch_all; patch_all()

import gevent
import gevent.socket
import socket
import signal
import sys
from scapy.all import TCP, IP
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
    con = get_connection(ip.src, ip.dst, tcp.sport, tcp.dport)
    pp("Application:", ip, con)

    # existing connection
    if con is not None: 
        return con.pkt_outgoing(pkt, ip, tcp)

    # new connection
    else:
        con = get_old_connection(ip.src, ip.dst, tcp.dport)
        
        # recovery for connect (port switched)
        if con is not None:
            return con.pkt_outgoing(pkt, ip, tcp)

        # does not support 2 wawy handshake
        if tcp.flags & SYN:
            # new connection
            # should be SYN for outgoing connection
            # SYN + ACK for incomming connection
            con = Connection(ip.src, ip.dst, tcp.sport, tcp.dport, True) 

            pp("new Connection:", ip)
            con.register()

    return _accept(pkt)


def tcpr_peer(pkt):
    ip = IP(pkt.get_payload())
    tcp = ip.getlayer(TCP)
    con = get_connection(ip.dst, ip.src, tcp.dport, tcp.sport)

    #this is only for msgs geverated inhouse can be aviouded by better design
    if con is None:
        con = get_old_connection(ip.dst, ip.src, tcp.sport)

    pp("Peer:", ip, con)

    if con is not None:
        return con.pkt_incomming(pkt, ip, tcp)

    
    print("Did not find any connection")
    return _accept(pkt)


def keypress():
    while True:
        gevent.socket.wait_read(sys.stdin.fileno())
        msg = sys.stdin.readline()
        if msg.strip() == "r": 
            print("Recovering")
            for connection in connections:
                connection.recover_syn()
            continue

        if msg.strip() == "c": 
            print("Clearing")
            while connections:
                connections.pop().reset()

            continue

if __name__ == "__main__":
    app_thread = create_nfqueue_thread(0, tcpr_application)
    peer_thread = create_nfqueue_thread(1, tcpr_peer)
    input_thread = gevent.spawn(keypress)

    gevent.joinall([app_thread, peer_thread])
