from scapy.all import TCP, IP, send
import enum

connections = []

FIN=0x01
SYN=0x02
RST=0x04
PSH=0x08
ACK=0x10
URG=0x20
ECE=0x40
CWR=0x80


STATES = enum.Enum("TCP_STATE", [
    "CLOSED",
    "LISTEN",
    "SYN_RCV",
    "SYN_SENT",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIX_WAIT_2",
    "LAST_ACK",
    "CLOSING",
    "CLOSE_WAIT"])

def pp(msg, ip, con=None):
    tcp = ip[1]
    msg = "{:20} {}:{}-->{}:{} flags {:4} {:10}/{:10}".format(msg, ip.src, tcp.sport, ip.dst, tcp.dport, tcp.flags.flagrepr(), tcp.seq, tcp.ack)
    if con is not None:
        msg += ", con_down: {}".format(con.con_down)
    print(msg)

def _drop(pkt):
    pp("Dropping", IP(pkt.get_payload()))
    pkt.drop()

def _accept(pkt):
    pp("Acceepting", IP(pkt.get_payload()))
    pkt.accept()

def send_local(msg, pkt):
    ip = pkt
    tcp = pkt[1]
    pp("Local " + msg, ip)
    send(pkt, iface="lo")


class Connection:
    __slots__ = [
            'local_addr',
            'local_port',
            'remote_addr',
            'remote_port',
            'initial_local_port',
            'local_seq',
            'remote_seq',
            'con_down',
            'is_bind',
            'state',
            'delta']

    def __init__(self, local_ip, remote_ip, local_port, remote_port, is_bind):
        self.local_addr = local_ip
        self.local_port = local_port
        self.remote_addr = remote_ip
        self.remote_port = remote_port
        self.initial_local_port = local_port
        self.delta = 0
        self.is_bind = is_bind
        self.local_seq = 0
        self.remote_seq = 0
        self.con_down = 0
        self.state = STATES.ESTABLISHED

    incomming = {}
    outgoing = {}

    def register_state(state, direction):
        def _f(func):
            direction[state] = func
            return func

        return _f


    @register_state(STATES.ESTABLISHED, outgoing)
    def on_established_outgoing(pkt, ip, tcp):
        if FIN & tcp.flags:
            self.end_fin()
            # time wait?!?
            self.state = STATES.CLOSED
            return _drop(pkt)

        if RST & tcp.flags:
            self.state = STATES.CLOSED
            return _drop(pkt)



    def pass_pkt(pkt, ip, tcp):
        return _accept(pkt)

    def pkt_incomming(pkt, ip, tcp):
        self.incoming.get(self.state, self.pass_pkt)(pkt, ip ,tcp)

    def pkt_outgoing(pkt, ip, tcp):
        self.outgoing.get(self.state, self.pass_pkt)(pkt, ip, tcp)
        

    def register(self):
        connections.append(self)

    def recover_syn(self):
        if not self.is_bind:
            return

        ip = IP(
            src=self.remote_addr,
            dst=self.local_addr,
            flags=0x02)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=self.remote_seq - 1,
            ack=0,
            flags = "S")

        send_local("SYN recover", ip/tcp)

    def recover_ack(self, tcp):
        if not self.is_bind:
            return

        self.delta = tcp.seq + 1 - self.local_seq
        self.local_seq = tcp.seq + 1
        ip = IP(
            src=self.remote_addr,
            dst=self.local_addr)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=self.remote_seq,
            ack=self.local_seq,
            flags = "A")

        send_local("ACK", ip/tcp)

    def end_fin(self):
        ip = IP(
            src=self.remote_addr,
            dst=self.local_addr)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=self.remote_seq,
            ack=self.local_seq + 1,
            flags="FA")

        send_local("FIN", ip/tcp)


def get_connection(local_addr, remote_addr, local_port, remote_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.local_port == local_port and \
            connection.remote_port == remote_port:
                return connection
    return None


def get_old_connection(local_addr, remote_addr, local_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.local_port == local_port:
                return connection
    return None


def get_dup_connection(local_addr, remote_addr, remote_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.remote_port == remote_port:
                return connection
    return None
    
