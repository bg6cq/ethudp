# Cross Internet, connect your ethernets
# 通过互联网桥接2个以太网段

使用EthUDP可以把两个以太网通过互联网桥接，下面是我们的一个案例：

开通视频会议时，如果某一方的视频会议终端在内网，对外经过了NAT或防火墙设备连接互联网，
另一方终端在互联网上，这种情况经常会出现某个方向的音频或视频无法传送的问题。

解决问题的最简单方法是把两方的内部以太网通过互联网直接桥接，让两边的视频终端直通即可。


## 网络结构

站点A有公网IP，IP地址是202.110.92.27/29，网关是202.110.92.25。

站点B经过NAT连接互联网，IP地址是192.168.10.2/24(内网)，网关是192.168.10.1。

站点A和站点B各有一台视频会议终端，站点A的视频会议终端IP是 10.10.10.1/24，
站点B的视频会议终端IP是10.10.10.2/24。

为了将站点A和站点B的以太网互联，在站点A和站点B各增加一台Linux机器提供隧道连接，拓扑图如下：

![网络拓扑图](vcnet.png)

## 使用设备

Linux机器，我们采购的是
[N10Plus多网口千兆迷你小主机](https://detail.tmall.com/item.htm?id=542409856806)

N10Plus有4个千兆接口，无风扇运行，外形如下：

![N10Plus多网口千兆迷你小主机](n10plus.jpg)

## 系统安装

两台Linux机器为CentOS 6 最小安装(eth0网卡分别设置各自IP地址和网关)，执行以下命令安装EthUDP软件：
```
yum install epel-release 
yum install gcc git lz4-devel openssl-devel tcpdump ntpdate telnet traceroute
cd /usr/src
git clone https://github.com/bg6cq/ethudp.git
cd ethudp
make
```

## 站点A Linux机器的设置：

1. 允许udp 6000、6001端口的通信

```
iptables -I INPUT -j ACCEPT -p udp --dport 6000
iptables -I INPUT -j ACCEPT -p udp --dport 6001
service iptables save
```
2. 修改文件 `/etc/rc.d/rc.local`

```
ethtool -K eth1 gro off
ip link set eth1 up

OPT="-k 123456 -enc aes-128 -p password"
/usr/src/ethudp/EthUDP -e $OPT 222.110.92.27 6000 0.0.0.0 0 eth1
/usr/src/ethudp/EthUDP -i $OPT 222.110.92.27 6001 0.0.0.0 0 172.16.10.1 24
````

## 站点B Linux机器的设置：

1. 修改文件 `/etc/rc.d/rc.local`

```
ethtool -K eth1 gro off
ip link set eth1 up

OPT="-k 123456 -enc aes-128 -p password"
/usr/src/ethudp/EthUDP -e $OPT 192.168.10.2 6000 222.110.92.27 6000 eth1
/usr/src/ethudp/EthUDP -i $OPT 192.168.10.2 6001 222.110.92.27 6001 172.16.10.2 24
````

## 配置说明

以上设置的含义是：

* 站点A和站点B间的Linux机器使用UDP 6000和6001端口通信
* 站点B的Linux通过NAT连接站点A的Linux
* 通信时使用AES-128加密
* 站点A/站点B的视频会议终端能直接通信，就像两者直连一样
* 站点A/站点B的Linux可以使用172.16.10.1/172.16.10.2互相通信
