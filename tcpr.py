from gevent.monkey import patch_all; patch_all()

import nanomsg
import gevent
import gevent.socket
import socket
import signal
import sys

from tcpr_pb2 import tcpr, client
from ipaddress import ip_address
from scapy.all import TCP, IP, IPv6
from netfilterqueue import NetfilterQueue, Packet
from connection import Connection, get_connection
from connection import connections, get_old_connection
from utils import pp, _accept


pudb_active = False
Running = True
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


def tcpr4_application(pkt):
    ip = IP(pkt.get_payload())
    return tcpr_application(pkt, ip)

def tcpr6_application(pkt):
    ip = IPv6(pkt.get_payload())
    return tcpr_application(pkt, ip)

def tcpr_application(pkt, ip):
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

    return _accept(pkt, ip)


def tcpr4_peer(pkt):
    ip = IP(pkt.get_payload())
    return tcpr_peer(pkt, ip)

def tcpr6_peer(pkt):
    ip = IPv6(pkt.get_payload())
    return tcpr_peer(pkt, ip)

def tcpr_peer(pkt, ip):
    tcp = ip.getlayer(TCP)
    con = get_connection(ip.dst, ip.src, tcp.dport, tcp.sport)

    #this is only for msgs geverated inhouse can be aviouded by better design
    if con is None:
        con = get_old_connection(ip.dst, ip.src, tcp.sport)

    pp("Peer:", ip, con)

    if con is not None:
        return con.pkt_incomming(pkt, ip, tcp)

    
    print("Did not find any connection")
    return _accept(pkt, ip)


def keypress():
    while True:
        try:
            gevent.socket.wait_read(sys.stdin.fileno())
            msg = sys.stdin.readline().strip()
            if msg == "r": 
                print("Recovering")
                for connection in connections:
                    connection.recover()
                continue

            if msg == "c": 
                print("Clearing")
                while connections:
                    connections.pop().reset()
                continue

            if msg == "l":
                for connection in connections:
                    ip_type = IP 
                    addr = connection.remote_addr
                    if ip_address(addr).version == 6:
                        ip_type = IPv6

                    dummy_pkt = ip_type( src=connection.local_addr,
                                         dst=connection.remote_addr)/TCP( 
                                sport=connection.local_port,
                                dport=connection.remote_port,
                                ack=connection.remote_seq,
                                seq=connection.local_seq)
                    pp("Connection:", dummy_pkt, connection)
                continue

            print('''Commands:
            r -- recover connections
            c -- clear connections
            l -- list connections''')
        except Exception as e:
            print(e)

def build_get_response():
    msg = tcpr()
    msg.get_response.clients.extend([ client(
                local_ip=connection.local_addr,
                remote_ip=connection.remote_addr,
                local_port=connection.local_port,
                remote_port=connection.remote_port,
                local_seq=connection.local_seq,
                remote_seq=connection.remote_seq,
                is_server=connection.is_bind,
                init_local_seq=0)
        for connection in connections])
    return msg.SerializeToString()

def set_connections(msg):
    while connections:
        connections.pop()

    for con in msg.set.clients:
        con = Connection(
                local_ip=con.local_ip,
                remote_ip=con.remote_ip,
                local_port=con.local_port,
                remote_port=con.remote_port,
                is_bind=con.is_server,
                local_seq=con.local_seq,
                remote_seq=con.remote_seq)
        con.register()
        con.recover()
        

    resp = tcpr()
    resp.set_response.SetInParent()
    return resp.SerializeToString()

def control_server():
    s = nanomsg.Socket(nanomsg.REP)
    s.recv_timeout = 0
    s.bind("tcp://0.0.0.0:54748")
    while True:
        gevent.socket.wait_read(s.recv_fd)
        msg = tcpr.FromString(s.recv())
        mtype = msg.WhichOneof('message')
        if mtype == 'get':
            s.send(build_get_response())

        if mtype == 'set':
            s.send(set_connections(msg))


if __name__ == "__main__":
    app_thread = create_nfqueue_thread(0, tcpr4_application)
    peer_thread = create_nfqueue_thread(1, tcpr4_peer)
    app_thread = create_nfqueue_thread(2, tcpr6_application)
    peer_thread = create_nfqueue_thread(3, tcpr6_peer)
    input_thread = gevent.spawn(keypress)
    control_server = gevent.spawn(control_server)

    gevent.joinall([app_thread, peer_thread])
