EthUDP
======

Ethernet over UDP

Bridge two ethernets using UDP


     |                             |
     |                             |
     |    |                        |    |
     |    |                        |    |
 eth0|    |eth1                eth0|    |eth1
+----+----+----+              +----+----+----+
|   server A   |              |   server B   |
+--------------+              +--------------+

Each server connects Internet via interface eth0.
server A IP is IPA
server B IP is IPB

run following command in server A
ip link set eth1 up
ifconfig eth1 mtu 1508
./EthUDP IPA 6000 IPB 6000 eth1


run following command in server B
ip link set eth1 up
ifconfig eth1 mtu 1508
./EthUDP IPB 6000 IPA 6000 eth1

will bridge eth1 of two host via internet UDP port 6000

how it works:
1. open raw socket for eth1
2. open udp socket to remote host
3. if read packet from raw socket, send to udp socket
4. if read packet from udp socket, send to raw socket
