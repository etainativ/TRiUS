import nanomsg
import tcpr_pb2

cons = []

def print_entry(con, extra):
    print("{}:{:5} --> {}:{:5}, {}".format(
        con.local_ip, con.local_port, con.remote_ip, con.remote_port, extra))

def print_menu():
    print('''1. show server list
2. update list
3. show list
4. set list''')

def connect():
    s = nanomsg.Socket(nanomsg.REQ)
    s.connect("tcp://0.0.0.0:54748")
    return s

def get_from_server(s):
    p = tcpr_pb2.tcpr()
    p.get_list.SetInParent()
    s.send(p.SerializeToString())
    resp = tcpr_pb2.tcpr.FromString(s.recv())
    return resp.get_list_response.connections


def menu():
    global cons
    s = connect()
    p = tcpr_pb2.tcpr()
    print_menu()
    while True:
        x = input()

        if x == '1':
            for c in get_from_server(s):
                print_entry(c.connection, "mss: {}, ws: {}, sack: {}".format(
                    c.max_segment_size, c.window_scaling, c.sack_enabled))
            continue

        if x == '2':
            cons = get_from_server(s)
            continue

        if x == '3':
            for c in cons:
                print_entry(c.connection, "mss: {}, ws: {}, sack: {}".format(
                    c.max_segment_size, c.window_scaling, c.sack_enabled))
            continue

        if x == '4':
            for c in cons:
                p.set.CopyFrom(c)
                s.send(p.SerializeToString())
                resp = tcpr_pb2.tcpr.FromString(s.recv())
                msg = "SUCCESS" if resp.set_response.status == tcpr_pb2.SUCCESS else "FAILED"
                print_entry(c.connection, msg)
            continue
        print_menu()
            
        

if __name__ == "__main__":
    menu()
