from gevent.monkey import patch_all; patch_all()

import nanomsg
import gevent
import gevent.socket
import socket
import signal
import sys

import tcpr_pb2
from ipaddress import ip_address
from scapy.all import TCP, IP, IPv6
from netfilterqueue import NetfilterQueue, Packet
from connection import Connection, get_connection_peer
from connection import connections, get_old_connection
from connection import get_connection_application
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
    con = get_connection_application(ip.src, ip.dst, tcp.sport, tcp.dport)
    pp("Application:", ip, con)

    # recovery for connect (port switched)
    if con is None and tcp.flags == SYN:
        con = get_old_connection(ip.src, ip.dst, tcp.dport)

    # existing connection
    if con is not None: 
        return con.pkt_outgoing(pkt, ip, tcp)

    if tcp.flags & SYN:
        # new connection
        # should be SYN for outgoing connection
        # SYN + ACK for incomming connection
        con = Connection(ip.src, ip.dst, tcp.sport, tcp.dport, True) 

        options = dict(tcp.options)
        sack = 1 if "SAckOK" in options else 0
        mss = options.get("MSS", None)
        wscale = options.get("WScale", None)
        con = Connection(
                local_ip=ip.src,
                remote_ip=ip.dst,
                local_port=tcp.sport,
                remote_port=tcp.dport,
                is_bind=False,
                mss=mss,
                ws=wscale,
                sack=sack,
                initial_seq=tcp.seq + 1)
        con.register()
        pp("New Connect:", ip, con)

    return _accept(pkt, ip)

def tcpr4_peer(pkt):
    ip = IP(pkt.get_payload())
    return tcpr_peer(pkt, ip)

def tcpr6_peer(pkt):
    ip = IPv6(pkt.get_payload())
    return tcpr_peer(pkt, ip)

def tcpr_peer(pkt, ip):
    tcp = ip.getlayer(TCP)
    con = get_connection_peer(ip.dst, ip.src, tcp.dport, tcp.sport)

    #this is only for msgs geverated inhouse can be aviouded by better design
    if con is None:
        con = get_old_connection(ip.dst, ip.src, tcp.sport)

    if con is None and tcp.flags == "S":
        options = dict(tcp.options)
        sack = 1 if "SAckOK" in options else 0
        mss = options.get("MSS", None)
        wscale = options.get("WScale", None)
        con = Connection(
                local_ip=ip.dst,
                remote_ip=ip.src,
                local_port=tcp.dport,
                remote_port=tcp.sport,
                is_bind=True,
                mss=mss,
                ws=wscale,
                sack=sack)
        con.register()
        pp("New Accept:", ip, con)

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

def get_init_response(con):
    msg = tcpr_pb2.tcpr()
    connection = get_connection_peer(
            con.local_ip,
            con.remote_ip,
            con.local_port,
            con.remote_port)

    if connection is None:
        msg.get_init_response.status = tcpr_pb2.FAILED_NOT_FOUND
        return msg.SerializeToString()

    msg.get_init_response.initial_seq = connection.initial_seq
    msg.get_init_response.sack_enabled = connection.sack
    msg.get_init_response.max_segment_size = connection.mss
    msg.get_init_response.window_scaling = connection.ws
    msg.get_init_response.status = tcpr_pb2.SUCCESS
    return msg.SerializeToString()

def get_ack_response(con):
    msg = tcpr_pb2.tcpr()
    connection = get_connection_peer(
            con.local_ip,
            con.remote_ip,
            con.local_port,
            con.remote_port)

    if connection is None:
        msg.get_ack_response.status = tcpr_pb2.FAILED_NOT_FOUND
        return msg.SerializeToString()

    msg.get_ack_response.current_ack = connection.local_seq
    msg.get_ack_response.status = tcpr_pb2.SUCCESS
    return msg.SerializeToString()

def set_connections(set_msg):
    resp = tcpr_pb2.tcpr()
    con = set_msg.connection

    if get_old_connection(
        con.local_ip,
        con.remote_ip,
        con.remote_port) is not None:
        resp.set_response.status = tcpr_pb2.FAILED_EXISTS
        return resp.SerializeToString()
            
    connection = Connection(
            local_ip=con.local_ip,
            remote_ip=con.remote_ip,
            local_port=con.local_port,
            remote_port=con.remote_port,
            is_bind=False,
            mss=set_msg.max_segment_size,
            ws=set_msg.window_scaling,
            sack=set_msg.sack_enabled)
    connection.register()
    connection.recover()
        
    resp.set_response.status = tcpr_pb2.SUCCESS 
    return resp.SerializeToString()

def create_list_response():
    resp = tcpr_pb2.tcpr()
    
    for connection in connections:
        entry = tcpr_pb2.tcpr_set()
        entry.connection.local_ip = connection.local_addr
        entry.connection.remote_ip = connection.remote_addr
        entry.connection.local_port = connection.local_port
        entry.connection.remote_port = connection.remote_port
        entry.sack_enabled = connection.sack
        entry.max_segment_size = connection.mss
        entry.window_scaling = connection.ws
        resp.get_list_response.connections.extend([entry])
    

    return resp.SerializeToString()

def control_server():
    s = nanomsg.Socket(nanomsg.REP)
    s.recv_timeout = 0
    s.bind("tcp://0.0.0.0:54748")
    while True:
        gevent.socket.wait_read(s.recv_fd)
        msg = tcpr_pb2.tcpr.FromString(s.recv())
        mtype = msg.WhichOneof('message')
        if mtype == 'get_list':
            s.send(create_list_response())

        if mtype == 'get_init':
            s.send(get_init_response(msg.get_init.connection))

        if mtype == 'get_ack':
            s.send(get_ack_response(msg.get_ack.connection))

        if mtype == 'set':
            s.send(set_connections(msg.set))


if __name__ == "__main__":
    app_thread = create_nfqueue_thread(0, tcpr4_application)
    peer_thread = create_nfqueue_thread(1, tcpr4_peer)
    app_thread = create_nfqueue_thread(2, tcpr6_application)
    peer_thread = create_nfqueue_thread(3, tcpr6_peer)
    input_thread = gevent.spawn(keypress)
    control_server = gevent.spawn(control_server)

    gevent.joinall([app_thread, peer_thread])
