import nanomsg
s = nanomsg.Socket(nanomsg.REQ)
from tcpr_pb2 import tcpr, client
p = tcpr()
p.get.SetInParent()
s.connect("tcp://0.0.0.0:54748")
s.send(p.SerializeToString())
res = tcpr.FromString(s.recv())
print(res)

open("external_test", "wb").write(res.SerializeToString())
