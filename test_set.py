import nanomsg
s = nanomsg.Socket(nanomsg.REQ)
from tcpr_pb2 import tcpr, client

p = tcpr()
p.set.SetInParent()
s.connect("tcp://0.0.0.0:54748")
s.send(p.SerializeToString())
res = tcpr.FromString(open("external_test", "rb").read())
print(res)

p.set.clients.extend(res.get_response.clients)
p.set.SetInParent()
print("sending")
print(p)

s.send(p.SerializeToString())
print(tcpr.FromString(s.recv()))



