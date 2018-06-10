ip netns add a2

ip l add p1 type veth peer name p2
ip l set netns a2 dev p2

ip a add 1.1.1.1/24 dev p1
ip a add 1::1/24 dev p1
ip l set up p1

ip netns exec a2 ip a add 1.1.1.2/24 dev p2
ip netns exec a2 ip a add 1::2/24 dev p2
ip netns exec a2 ip l set up p2

iptables -I OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --sport 1234 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p tcp -m tcp --dport 1234 -j NFQUEUE --queue-num 0
iptables -A INPUT -p tcp -m tcp --dport 1234 -j NFQUEUE --queue-num 1
iptables -A INPUT -p tcp -m tcp --sport 1234 -j NFQUEUE --queue-num 1


ip6tables -I OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -p tcp -m tcp --sport 1234 -j NFQUEUE --queue-num 2
ip6tables -A OUTPUT -p tcp -m tcp --dport 1234 -j NFQUEUE --queue-num 2
ip6tables -A INPUT -p tcp -m tcp --dport 1234 -j NFQUEUE --queue-num 3
ip6tables -A INPUT -p tcp -m tcp --sport 1234 -j NFQUEUE --queue-num 3
