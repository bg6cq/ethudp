# EthUDP

Ethernet over UDP, similar of VXLAN, transport Ethernet packet via UDP, support data encryption, udp connection failover

## Sample config

[Cross Internet, connect your ethenets/通过互联网桥接2个以太网段](sample2/README.md)

[Sample config](sample/README.md)

## package needs to compile

CentOS:
````
openssl-devel lz4-devel libpcap-devel
````
Debian
````
libssl-dev liblz4-dev libpcap-dev
````
and Debian liblz4 miss LZ4_compress_fast, you need rebuild it as https://github.com/facebook/mcrouter/issues/149
````
apt-get install dpkg-dev debhelper
echo "deb-src http://ftp.de.debian.org/debian/ stretch main" > /etc/apt/sources.list.d/stretch-source-packages.list
apt-get update
apt-get source lz4=0.0~r131-2
cd lz4-0.0~r131
dpkg-buildpackage -rfakeroot -uc -b
cd ..
dpkg -i liblz4-1_0.0~r131-2_amd64.deb liblz4-dev_0.0~r131-2_amd64.deb
````

## Increasing Linux kernel network buffers

For better performance, increase the UDP receive buffer size from 128K to 32MB
````
sysctl -w net.core.rmem_max=33554432
````

## 1. mode e
Bridge two ethernets using UDP

<pre>
          |-------Internet---------|
          |                        |
          |                        |
          |IPA                  IPB|
          |eth0                eth0|
+---------+----+              +----+---------+
|   server A   |              |   server B   |
+------+-------+              +-------+------+
       | eth1                    eth1 |
       |                              |
       |                              |
       |                              |
  +----+---+                     +----+----+
  | HOST 1 |                     |  HOST 2 |
  +--------+                     +---------+
</pre>

Each server connects Internet via interface eth0, IP is IPA & IPB.

On server A, run following command
````
ip link set eth1 up
ethtool -K eth1 gro off
ifconfig eth1 mtu 1508
./EthUDP -e IPA 6000 IPB 6000 eth1
````

On server B, run following command
````
ip link set eth1 up
ethtool -K eth1 gro off
ifconfig eth1 mtu 1508
./EthUDP -e IPB 6000 IPA 6000 eth1
````

bridge HOST 1 and HOST 2 via internet using UDP port 6000

how it works:
* open raw socket for eth1
* open udp socket to remote host
* read packet from raw socket, send to udp socket
* read packet from udp socket, send to raw socket

## 2. mode i
create a tap tunnel interface using UDP
<pre>
       |------------Internet--------------|
       |                                  |
       |                                  |
       |IPA                            IPB|
       |eth0                          eth0|
+------+-------+                  +-------+------+
|   server A   +--IP1--------IP2--+   server B   |
+--------------+                  +--------------+
</pre>

Each server connects Internet via interface eth0, IP is IPA & IPB.

On server A, run following command
````
./EthUDP -i IPA 6000 IPB 6000 IP1 masklen
````

On server B, run following command
````
./EthUDP -i IPB 6000 IPA 6000 IP2 masklen
````

create a tap tunnel interface and setup IP1/masklen IP2/masklen via internet using UDP port 6000

how it works:
* open tap raw socket, setip addr
* open udp socket to remote host
* read packet from raw socket, send to udp socket
* read packet from udp socket, send to raw socket


## 3. mode b
create a tap tunnel interface using UDP
<pre>
       |------------Internet--------------|
       |                                  |
       |                                  |
       |IPA                            IPB|
       |eth0                          eth0|
+------+-------+                  +-------+------+
|   server A   +--bridge----bridge|   server B   |
+------+-------+                  +-------+------+
       |eth1                          eth1|
       |                                  |
       |                                  |
  +----+---+                         +----+----+
  | HOST 1 |                         |  HOST 2 |
  +--------+                         +---------+
</pre>

Each server connects Internet via interface eth0, IP is IPA & IPB.

On server A, run following command
````
brctl addbr br0
ip link set eth1 up
brctl addif br0 eth1
./EthUDP -b IPA 6000 IPB 6000 br0
````

On server B, run following command
````
brctl addbr br0
ip link set eth1 up
brctl addif br0 eth1
./EthUDP -b IPB 6000 IPA 6000 br0
````

create a tap tunnel interface and add to br0 internet using UDP port 6000,
Host 1 and Host 2 can communicate with each other.

how it works:
* open tap raw socket, run shell `brctl add if ??? tap?` add to bridge
* open udp socket to remote host
* read packet from raw socket, send to udp socket
* read packet from udp socket, send to raw socket


## 4. mode t

using libpcap to capture packets and send full ethernet packet to remote site

## 5. mode u

using libpcap to capture udp packets and send udp packet to remote site

## Note:
1. support 802.1Q VLAN frame transport

NIC MTU should set to 1504 or 1508, for single 802.1Q or double 802.1Q tag. But some NICs do not allow change the default 1500.

2. support automatic tcp mss fix

3. if your NIC support GRO, you should disable it by
````
ethtool -K eth1 gro off
````

4. support connection from NATed server

If server A has public IP, while server B connect from NATed IP, please run (port is 0)
````
./EthUDP -e -p password IPA 6000 0.0.0.0 0 eth1 in A
./EthUDP -e -p password IPB 6000 IPA 6000 eth1 in B
````
5. support master slave switchover

Using master udp connection, switch to slave if master down(send/recv ping/pong message 1/sec)
````
./EthUDP ... IPA portA IPB portB ... SlaveIPA SlaveportA SlaveIPB SlaveportB
./EthUDP ... IPB portB IPA portA ... SlaveIPB SlaveportB SlaveIPA SlaveportA
````
6. support AES-128/192/256 encrypt/decrypt UDP traffic
````
./EthUDP ... -enc aes-128 -k aes_key ...
````
7. support LZ4 compress
````
./EthUDP ... -lz4 1 ...
````
8. support VLAN maping
````
./EthUDP ... -m vlanmap.txt ...

vlanmap.txt
#my_vlan remote_vlan
10 30
40 100
````
9. support UDP packet fragment

```
./EthUDP ... -mtu 1500
```
split UDP packet length exceed 1500 bytes to two UDP packets
