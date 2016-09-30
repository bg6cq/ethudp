<pre>
EthUDP
======
<pre>
Ethernet over UDP

1. mode e
Bridge two ethernets using UDP

          |-------Internet---------|
          |                        |
     |    |                        |    |
     |    |IPA                  IPB|    |
 eth1|    |eth0                eth0|    |eth1
+----+----+----+              +----+----+----+
|   server A   |              |   server B   |
+--------------+              +--------------+

Each server connects Internet via interface eth0, IP is IPA & IPB.

On server A, run following command
ip link set eth1 up
ifconfig eth1 mtu 1508
./EthUDP -e IPA 6000 IPB 6000 eth1

On server B, run following command
ip link set eth1 up
ifconfig eth1 mtu 1508
./EthUDP -e IPB 6000 IPA 6000 eth1

will bridge eth1 of two hosts via internet using UDP port 6000

how it works:
* open raw socket for eth1
* open udp socket to remote host
* read packet from raw socket, send to udp socket
* read packet from udp socket, send to raw socket

2. mode i
create a tap tunnel interface using UDP

       |------------Internet--------------|
       |                                  |
       |                                  |
       |IPA                            IPB|
       |eth0                          eth0|
+------+-------+                  +-------+------+
|   server A   +--IP1--------IP2--+   server B   |
+--------------+                  +--------------+

Each server connects Internet via interface eth0, IP is IPA & IPB.

On server A, run following command
./EthUDP -i IPA 6000 IPB 6000 IP1 masklen

On server B, run following command
./EthUDP -i IPB 6000 IPA 6000 IP2 masklen

will create a tap tunnel interface and setup IP1/masklen IP2/masklen via internet using UDP port 6000

how it works:
* open tap raw socket, setip addr
* open udp socket to remote host
* read packet from raw socket, send to udp socket
* read packet from udp socket, send to raw socket

Note:
1. support 802.1Q VLAN frame transport
2. support automatic tcp mss fix
3. support connection from NATed server
If server B connect from NAT IP, please run
./EthUDP -e -p password IPA 6000 0.0.0.0 0 eth1 in A
./EthUDP -e -p password IPB 6000 IPA 6000 eth1 in B
</pre>
