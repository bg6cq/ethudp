# EthUDP

Ethernet over UDP, 类似 VXLAN，通过 UDP 传输以太网数据包，支持数据加密、UDP 连接主备切换。

---

## 中文文档

### 简介

EthUDP 将两个以太网段通过互联网桥接，支持 5 种运行模式。数据经过 LZ4 压缩（可选）和加密（XOR 或 AES-128/192/256）后通过 UDP 传输。

### 配置示例

[通过互联网桥接2个以太网段](sample2/README.md)

[基本配置示例](sample/README.md)

### 编译依赖

CentOS:
````
openssl-devel lz4-devel libpcap-devel
````
Debian:
````
libssl-dev liblz4-dev libpcap-dev
````

Debian 的 liblz4 可能缺少 LZ4_compress_fast，需重新编译（参考 https://github.com/facebook/mcrouter/issues/149）：
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

### 增大内核网络缓冲区

建议将 UDP 接收缓冲区从 128K 增大到 32MB：
````
sysctl -w net.core.rmem_max=33554432
````

---

### 1. mode e — 原始以太网桥接

通过 UDP 桥接两个以太网段。

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

服务器 A：
````
ip link set eth1 up
ethtool -K eth1 gro off
ifconfig eth1 mtu 1508
./EthUDP -e IPA 6000 IPB 6000 eth1
````

服务器 B：
````
ip link set eth1 up
ethtool -K eth1 gro off
ifconfig eth1 mtu 1508
./EthUDP -e IPB 6000 IPA 6000 eth1
````

工作原理：
* 打开 eth1 的 raw socket
* 打开到远端的 UDP socket
* 从 raw socket 读取数据包，发送到 UDP socket
* 从 UDP socket 读取数据包，发送到 raw socket

---

### 2. mode i — Tap 隧道接口

创建 tap 隧道接口并配置 IP。

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

服务器 A：
````
./EthUDP -i IPA 6000 IPB 6000 IP1 masklen
````

服务器 B：
````
./EthUDP -i IPB 6000 IPA 6000 IP2 masklen
````

---

### 3. mode b — 网桥模式

创建 tap 接口并加入 brctl 网桥。

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

服务器 A：
````
brctl addbr br0
ip link set eth1 up
brctl addif br0 eth1
./EthUDP -b IPA 6000 IPB 6000 br0
````

服务器 B：
````
brctl addbr br0
ip link set eth1 up
brctl addif br0 eth1
./EthUDP -b IPB 6000 IPA 6000 br0
````

---

### 4. mode t — 全包捕获

使用 libpcap 捕获数据包，将完整以太网帧发送到远端。

### 5. mode u — UDP 捕获

使用 libpcap 捕获 UDP 数据包，只提取载荷（不含 UDP 头）发送到远端。

---

### 注意事项

1. **支持 802.1Q VLAN 帧传输** — 网卡 MTU 应设为 1504（单标签）或 1508（双标签）。

2. **支持 TCP MSS 自动修正**
````
./EthUDP ... -mss 1450 ...
````

3. **如网卡支持 GRO，需关闭**
````
ethtool -K eth1 gro off
````

4. **支持 NAT 环境连接**

   服务器 A 有公网 IP，服务器 B 在 NAT 后：
````
./EthUDP -e -p password IPA 6000 0.0.0.0 0 eth1   # 服务器 A（NAT 监听端）
./EthUDP -e -p password IPB 6000 IPA 6000 eth1     # 服务器 B（NAT 客户端）
````

5. **支持主备切换**

   使用主 UDP 连接，主连接断开后切换至备用（每秒 PING/PONG 检测）。
````
./EthUDP ... IPA portA IPB portB ... SlaveIPA SlaveportA SlaveIPB SlaveportB
````

6. **支持 AES-128/192/256 加密**

   如果 `-k` 未设置但使用了 `-enc`，默认密钥为 `"123456"`。如果 `-k` 已设置但未指定 `-enc`，默认使用 AES-128。
````
./EthUDP ... -enc aes-128 -k aes_key ...
````

7. **支持 LZ4 压缩**
````
./EthUDP ... -lz4 1 ...
````

8. **支持 VLAN 映射**
````
./EthUDP ... -m vlanmap.txt ...

vlanmap.txt
#本地VLAN 远端VLAN
10 30
40 100
````

9. **支持 UDP 分片**

   当数据包长度超过 `mtu - 28` 字节时拆分为两个分片。
````
./EthUDP ... -mtu 1500
````

---

## English Documentation

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

using libpcap to capture udp packets and send udp payload to remote site

## Note:
1. support 802.1Q VLAN frame transport

NIC MTU should set to 1504 or 1508, for single 802.1Q or double 802.1Q tag. But some NICs do not allow change the default 1500.

2. support automatic tcp mss fix
````
./EthUDP ... -mss 1450 ...
````

3. if your NIC support GRO, you should disable it by
````
ethtool -K eth1 gro off
````

4. support connection from NATed server

If server A has public IP, while server B connect from NATed IP, please run (port is 0)
````
./EthUDP -e -p password IPA 6000 0.0.0.0 0 eth1   # server A (NAT listener)
./EthUDP -e -p password IPB 6000 IPA 6000 eth1     # server B (NAT client)
````
5. support master slave switchover

Using master udp connection, switch to slave if master down(send/recv ping/pong message 1/sec)
````
./EthUDP ... IPA portA IPB portB ... SlaveIPA SlaveportA SlaveIPB SlaveportB
./EthUDP ... IPB portB IPA portA ... SlaveIPB SlaveportB SlaveIPA SlaveportA
````
6. support AES-128/192/256 encrypt/decrypt UDP traffic

If `-k` is omitted with `-enc`, key defaults to `"123456"`. If `-k` is set without `-enc`, defaults to AES-128.
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
split UDP packets exceeding (mtu - 28) bytes into two fragments (1036 - 1500)
