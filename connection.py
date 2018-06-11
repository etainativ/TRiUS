from scapy.all import TCP, IP, IPv6, conf, L3RawSocket, L3RawSocket6, send
from utils import pp, _accept, _drop
import enum
import ipaddress

conf.L3socket = L3RawSocket
conf.verb = 0
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
    "RECOVER",
    "LISTEN",
    "SYN_RECV",
    "SYN_SENT",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIX_WAIT_2",
    "LAST_ACK",
    "CLOSING",
    "CLOSE_WAIT"])

def send_local(msg, pkt, socket_type):
    pp("Local " + msg, pkt)
    send(pkt, iface="lo", socket=socket_type())

def send_remote(msg, pkt, socket_type):
    pp("Remote " + msg, pkt)
    send(pkt, socket=socket_type())

def rebuild_pkt(pkt, ip):
    pkt.set_payload(ip.build())


class Connection:
    __slots__ = [
            'local_addr',
            'local_port',
            'remote_addr',
            'remote_port',
            'initial_local_port',
            'local_seq',
            'is_bind',
            'is_v6',
            'socket_type',
            'ip_type',
            'state',
            'delta']

    def __init__(
            self,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            is_bind,
            local_seq=0):
        self.local_addr = local_ip
        self.local_port = local_port
        self.remote_addr = remote_ip
        self.remote_port = remote_port
        self.initial_local_port = local_port
        self.delta = 0
        self.is_bind = is_bind
        self.local_seq = local_seq 

        is_v6 = ipaddress.ip_address(self.remote_addr).version == 6
        self.socket_type = L3RawSocket6 if is_v6 else L3RawSocket
        self.ip_type = IPv6 if is_v6 else IP 
        # the first time we initiatied the connection
        # the state is really STATES.SYN-SENT but next ack
        # will set the state toi STATES.ESTABLISHED
        self.state = STATES.ESTABLISHED

    incomming = {}
    outgoing = {}

    def register_state(state, direction):
        def _f(func):
            if state in direction:
                raise Exception("multyple {} definitions".format(state))
            direction[state] = func
            return func

        return _f

    def update_tcp(self, pkt, ip, tcp, is_ongoing):
        if is_ongoing:
            tcp.seq -= self.delta
            tcp.sport = self.initial_local_port

        else:
            self.local_seq = tcp.ack
            tcp.ack += self.delta
            tcp.dport = self.local_port

        del(tcp.chksum)
        pp("After update:", ip)
        rebuild_pkt(pkt, ip)

    @register_state(STATES.ESTABLISHED, outgoing)
    def on_established_outgoing(self, pkt, ip, tcp):
        if FIN & tcp.flags:
            self.end_fin(tcp)
            self.state = STATES.FIN_WAIT_1
            return _drop(pkt, ip)

        if RST & tcp.flags:
            self.state = STATES.CLOSED
            # rst sequence?
            return _drop(pkt, ip)

        self.update_tcp(pkt, ip, tcp, True)
        return _accept(pkt, ip)

    @register_state(STATES.ESTABLISHED, incomming)
    def on_established_incomming(self, pkt, ip, tcp):
        # TODO disconnect sequences
        self.update_tcp(pkt, ip, tcp, False)
        return _accept(pkt, ip)

    @register_state(STATES.SYN_RECV, outgoing)
    def on_syn_rcv_outgoing(self, pkt, ip, tcp):
        if ACK & tcp.flags:
            if SYN & tcp.flags:
                self.recover_ack(tcp)
            else:
                self.state = STATES.ESTABLISHED
        if RST & tcp.flags:
            self.state = STATES.CLOSED
            return _accept(pkt, ip)
        return _drop(pkt, ip)

    @register_state(STATES.SYN_RECV, incomming)
    def on_syn_rcv_outgoing(self, pkt, ip, tcp):
        if ACK == tcp.flags:
            self.state = STATES.ESTABLISHED
            return _accept(pkt, ip)
        return _drop(pkt, ip)

    @register_state(STATES.CLOSED, outgoing)
    def on_closed_outgoing(self, pkt, ip, tcp):
        if tcp.flags & SYN:
            self.state = STATES.RECOVER
            self.recover_seq_ack(pkt, ip, tcp)
            return _accept(pkt, ip)
        return _drop(pkt, ip)

    @register_state(STATES.RECOVER, incomming)
    def on_recover_incomming(self, pkt, ip, tcp):
        if tcp.flags & RST:
            print("Session RESTED by peer")
            connections.pop(self)

        if tcp.flags == ACK:
            self.state = STATES.SYN_SENT
            self.recover_syn_ack_local(tcp)
        
        return _drop(pkt, ip)

    @register_state(STATES.LISTEN, incomming)
    def on_listen_incomming(self, pkt, ip, tcp):
        if tcp.flags == ACK:
            self.recover_syn(tcp)

        if tcp.flags == SYN:
            self.state = STATES.SYN_RECV
            _accept(pkt, ip)

        return _drop(pkt, ip)

    @register_state(STATES.SYN_SENT, incomming)
    def on_syn_sent_incomming(self, pkt, ip, tcp):
        if tcp.flags & SYN and tcp.flags & ACK:
            self.state = STATES.SYN_RECV
            return _accept(pkt, ip)
        
        if tcp.flags & ACK:
            self.state = STATES.ESTABLISHED
            # should look into validity of the pkt
            return _accept(pkt, ip)
        return _drop(pkt, ip)

    @register_state(STATES.FIN_WAIT_1, incomming)
    def on_fin_wait_1(self, pkt, ip, tcp):
        # we dont distinguesh between fin_wait_1 and fin_wait_2
        if tcp.flags & FIN:
            self.state = STATES.CLOSED
            return _accept(pkt, ip)
        return _drop(pkt, ip)

    @staticmethod
    def pass_pkt_incomming(self, pkt, ip, tcp):
        self.update_tcp(pkt, ip, tcp, False)
        return _accept(pkt, ip)

    @staticmethod
    def pass_pkt_outgoing(self, pkt, ip, tcp):
        self.update_tcp(pkt, ip, tcp, True)
        return _accept(pkt, ip)

    def pkt_incomming(self, pkt, ip, tcp):
        func = self.incomming.get(self.state, self.pass_pkt_incomming)
        return func(self, pkt, ip ,tcp)

    def pkt_outgoing(self, pkt, ip, tcp):
        func = self.outgoing.get(self.state, self.pass_pkt_outgoing)
        return func(self, pkt, ip, tcp)
        
    def register(self):
        connections.append(self)

    def recover_seq_ack(self, pkt, ip, tcp):
        self.local_seq = tcp.seq
        self.local_port = tcp.sport
        tcp.flags = "A"
        rebuild_pkt(pkt, ip)

    def recover_syn(self, tcp):
        self.local_seq = tcp.ack
        ip = self.ip_type(
            src=self.remote_addr,
            dst=self.local_addr)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=tcp.seq - 1,
            ack=0,
            flags="S")

        send_local("SYN recover", ip/tcp, self.socket_type)

    def recover_syn_ack_local(self, tcp):
        self.local_seq += 1
        self.delta = self.local_seq - tcp.ack

        ip = self.ip_type(
            src=self.remote_addr,
            dst=self.local_addr)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=tcp.seq - 1,
            ack=(tcp.ack + self.delta) % (2 ** 32),
            flags = "SA")

        send_local("SYN-ACK", ip/tcp, self.socket_type)

    def recover(self):
        if not self.is_bind:
            return

        ip = self.ip_type(
                src=self.local_addr,
                dst=self.remote_addr)

        tcp = TCP(
                dport=self.remote_port,
                sport=self.local_port,
                seq=0,
                ack=0,
                flags="A")

        send_remote("ACK", ip/tcp, self.socket_type)
        self.state = STATES.LISTEN

    def recover_ack(self, tcp):
        self.delta = tcp.seq + 1 - self.local_seq
        ip = self.ip_type(
            src=self.remote_addr,
            dst=self.local_addr)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=tcp.ack,
            ack=tcp.seq + 1,
            flags="A")

        send_local("ACK", ip/tcp, self.socket_type)

    def end_fin(self, tcp):
        ip = self.ip_type(
            src=self.remote_addr,
            dst=self.local_addr)

        tcp = TCP(
            dport=self.local_port,
            sport=self.remote_port,
            seq=tcp.ack,
            ack=tcp.seq + 1,
            flags="FA")

        send_local("FIN", ip/tcp, self.socket_type)

    def reset(self):
        pass

def get_connection_peer(local_addr, remote_addr, local_port, remote_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.initial_local_port == local_port and \
            connection.remote_port == remote_port:
                return connection
    return None


def get_connection_application(local_addr, remote_addr, local_port, remote_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.local_port == local_port and \
            connection.remote_port == remote_port:
                return connection
    return None



def get_dup_connection(local_addr, remote_addr, local_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.local_port == local_port:
                return connection
    return None


def get_old_connection(local_addr, remote_addr, remote_port):
    for connection in connections:
        if connection.local_addr == local_addr and \
            connection.remote_addr == remote_addr and \
            connection.remote_port == remote_port:
                return connection
    return None
