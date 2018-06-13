from scapy.all import TCP

def pp(msg, ip, con=None):
    tcp = ip.getlayer(TCP)
    msg = "{:20} {}:{}-->{}:{} flags {:4} {:10}/{:10}".format(
            msg, ip.src, tcp.sport, ip.dst, tcp.dport,
            tcp.flags.flagrepr(), tcp.seq, tcp.ack)
    if con is not None:
        msg += ", {:12}".format(con.state)
    print(msg)

def _drop(pkt, ip):
    pp("Dropping", ip)
    pkt.drop()

def _accept(pkt, ip):
    pp("Acceepting", ip)
    pkt.accept()

