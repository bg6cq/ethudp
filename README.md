EthUDP
======

Ethernet over UDP

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
./EthUDP IPA 6000 IPB 6000 eth1

On server B, run following command
ip link set eth1 up
ifconfig eth1 mtu 1508
./EthUDP IPB 6000 IPA 6000 eth1

will bridge eth1 of two hosts via internet using UDP port 6000

how it works:
1. open raw socket for eth1
2. open udp socket to remote host
3. read packet from raw socket, send to udp socket
4. read packet from udp socket, send to raw socket

Note:
1. support 802.1Q VLAN frame transport
2. support automatic tcp mss fix
