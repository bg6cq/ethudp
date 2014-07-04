/* EthUDP: used to create transparent bridge over ipv4/ipv6 network
	  by james@ustc.edu.cn 2009.04.02

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
3. if your NIC support GRO, you should disable it by
   ethtool -K eth1 gro off
*/	

// uncomment the following line to enable automatic tcp mss fix
//#define FIXMSS   1

// comment the following line to disable DEBUG
//#define DEBUG		1

#ifdef DEBUG
#define PRINTPKT	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h> 
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h> 
#include <linux/if_packet.h>
#include <linux/if_ether.h> 
#include <netinet/ip.h> 
#include <netinet/ip6.h> 
#include <netinet/tcp.h> 
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAXLEN 			2048
#define MAX_PACKET_SIZE	2048
#define MAXFD   		64

#define max(a,b)        ((a) > (b) ? (a) : (b))
int daemon_proc;            /* set nonzero by daemon_init() */

struct _EtherHeader {
  uint16_t destMAC1;
  uint32_t destMAC2;
  uint16_t srcMAC1;
  uint32_t srcMAC2;
  uint32_t VLANTag;
  uint16_t type;
  int32_t  payload;
} __attribute__((packed));

typedef struct _EtherHeader EtherPacket;


volatile struct sockaddr_in remote_addr;
int32_t ifindex;
int fdudp, fdraw;
int nat = 0;

void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{	int	errno_save, n;
	char buf[MAXLEN];

	errno_save = errno;		/* value caller might want printed */
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		syslog(level, buf);
	} else {
		fflush(stdout);		/* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

void err_msg(const char *fmt, ...)
{ 	va_list	ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void err_quit(const char *fmt, ...)
{ 	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{ 	va_list	ap;
	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void daemon_init(const char *pname, int facility)
{ 	int i;
	pid_t pid;
	if ( (pid = fork()) != 0)
		exit(0);                        /* parent terminates */

	/* 41st child continues */
	setsid();                               /* become session leader */

	signal(SIGHUP, SIG_IGN);
	if ( (pid = fork()) != 0)
		exit(0);                        /* 1st child terminates */

	/* 42nd child continues */
	daemon_proc = 1;                /* for our err_XXX() functions */

	umask(0);                               /* clear our file mode creation mask */

	for (i = 0; i < MAXFD; i++)
		close(i);

	openlog(pname, LOG_PID, facility);
}

int transfamily = 0;

int udp_server(const char *host, const char *serv, socklen_t *addrlenp)
{ 	int	sockfd, n;
	int	on = 1;
	struct addrinfo hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) 
		err_quit("udp_server error for %s, %s", host, serv);
	ressave = res;

	do {
		transfamily = res->ai_family;
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;               /* error, try next one */
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, 1);
		if (bind(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;                  /* success */
        close(sockfd);          /* bind error, close and try next one */
   } while ( (res = res->ai_next) != NULL);

   if (res == NULL)        /* errno from final socket() or bind() */
		err_sys("udp_server error for %s, %s", host, serv);

	if (addrlenp)
   		*addrlenp = res->ai_addrlen;    /* return size of protocol address */

  	freeaddrinfo(ressave);

	return(sockfd);
}

int udp_xconnect(char *lhost,char*lserv,char*rhost,char*rserv)
{ 	int	sockfd, n;
	struct addrinfo hints, *res, *ressave;

	sockfd = udp_server(lhost,lserv,NULL);

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

   	if ( (n = getaddrinfo(rhost, rserv, &hints, &res)) != 0) 
   		err_quit("udp_xconnect error for %s, %s", rhost, rserv);
	ressave = res;

	if ( ((struct sockaddr_in*) res->ai_addr)->sin_port == 0 ) {
#ifdef DEBUG
		printf("port==0, is nat\n");
#endif
		nat = 1;
		memcpy((void *)&remote_addr, res->ai_addr, res->ai_addrlen);
		return sockfd;
	}

   	do {
   		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
       		break;          /* success */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL)        /* errno set from final connect() */
		err_sys("udp_xconnect error for %s, %s", rhost, rserv);

	freeaddrinfo(ressave);

	return(sockfd);
}


/**
 * Open a rawsocket for the network interface
 */
int32_t open_socket(char *ifname, int32_t *rifindex) 
{ 	unsigned char buf[MAX_PACKET_SIZE];
  	int32_t ifindex;
  	struct ifreq ifr;
  	struct sockaddr_ll sll;

  	int32_t fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  	if (fd == -1) 
    	err_sys("socket %s - ", ifname);

  	// get interface index
  	memset(&ifr, 0, sizeof(ifr));
  	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) 
    	err_sys("SIOCGIFINDEX %s - ", ifname);
  	ifindex = ifr.ifr_ifindex;
  	*rifindex = ifindex;

  	// set promiscuous mode
  	memset(&ifr, 0, sizeof(ifr));
  	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  	ioctl(fd, SIOCGIFFLAGS, &ifr);
  	ifr.ifr_flags |= IFF_PROMISC;
  	ioctl(fd, SIOCSIFFLAGS, &ifr);

  	memset(&sll, 0xff, sizeof(sll));
  	sll.sll_family = AF_PACKET;
  	sll.sll_protocol = htons(ETH_P_ALL);
  	sll.sll_ifindex = ifindex;
  	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) 
    	err_sys("bind %s - ", ifname);

  	/* flush all received packets. 
   	*
   	* raw-socket receives packets from all interfaces
   	* when the socket is not bound to an interface
   	*/
  	int32_t i;
  	do {
    	fd_set fds;
    	struct timeval t;
    	FD_ZERO(&fds);	
    	FD_SET(fd, &fds);
    	memset(&t, 0, sizeof(t));
    	i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
    	if (i > 0) {
      		recv(fd, buf, i, 0);
    	};

#ifdef DEBUG
		printf("interface %d flushed\n", ifindex);
#endif

  	} while (i);

#ifdef DEBUG
  	printf("%s opened (fd=%d interface=%d)\n", ifname, fd, ifindex);
	fflush(stdout);
#endif

  	return fd;
}


void printPacket(EtherPacket *packet, ssize_t packetSize, char *message) 
{
	struct timeval  tv;
	struct timezone tz;
	struct tm      *tm;
 
	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);
 
	printf("%02d%02d %02d:%02d:%02d.%06ld ", tm->tm_mon + 1, tm->tm_mday, 
		tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);

	if ( (ntohl(packet->VLANTag) >> 16) == 0x8100 )  // VLAN tag
		printf("%s #%04x (VLAN %d) from %04x%08x to %04x%08x, len=%d\n",
			message, ntohs(packet->type), ntohl(packet->VLANTag) & 0xFFF,
			ntohs(packet->srcMAC1), ntohl(packet->srcMAC2),
			ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	else
		printf("%s #%04x (no VLAN) from %04x%08x to %04x%08x, len=%d\n",
			message, ntohl(packet->VLANTag) >> 16,
			ntohs(packet->srcMAC1), ntohl(packet->srcMAC2),
			ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	fflush(stdout);
}

// function from http://www.bloof.de/tcp_checksumming, thanks to crunsh
u_int16_t tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[], u_int16_t dest_addr[], u_int16_t buff[])
{
    u_int16_t prot_tcp = 6;
    u_int32_t sum = 0 ;
    int nleft = len_tcp;
    u_int16_t *w = buff;
 
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
 
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
		sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
 
    /* add the pseudo header */
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
 
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
 
    // Take the one's complement of sum
    sum = ~sum;
 
    return ((u_int16_t) sum);
}

u_int16_t tcp_sum_calc_v6(u_int16_t len_tcp, u_int16_t src_addr[],u_int16_t dest_addr[], u_int16_t buff[])
{
    u_int16_t prot_tcp = 6;
    u_int32_t sum = 0 ;
    int nleft = len_tcp;
    u_int16_t *w = buff;
 
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
 
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
		sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
 
    /* add the pseudo header */
	int i;
	for ( i=0; i<8; i++ ) 
		sum = sum + src_addr[i] + dest_addr[i];
	
    sum += htons(len_tcp);   // why using 32bit len_tcp
    sum += htons(prot_tcp);
 
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
 
    // Take the one's complement of sum
    sum = ~sum;
 
    return ((u_int16_t) sum);
}

static unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
		return 1;
	else
		return opt[offset+1];
}

void fix_mss(u_int8_t *buf, int len)
{
	u_int8_t * packet;
	int i;
	int VLANdot1Q=0;

	if( len < 54 ) return;
	packet = buf +12; // skip ethernet dst & src addr
	len -=12;
	
	if( (packet[0] == 0x81) && (packet[1] == 0x00) ) { // skip 802.1Q tag 0x8100
		packet +=4;
		len -=4;
		VLANdot1Q=1;
	}
	if( (packet[0] == 0x08) && (packet[1] == 0x00) ) { // IPv4 packet 0x0800
		packet +=2;
		len -=2;
	
		struct iphdr *ip = (struct iphdr *) packet;
		if( ip->version != 4 ) return; // check ipv4
		if( ntohs(ip->frag_off) & 0x1fff ) return;  // not the first fragment
		if( ip->protocol != IPPROTO_TCP ) return; // not tcp packet
		if( ntohs(ip->tot_len) > len ) return;  // tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr*) (packet + ip->ihl *4);
		if( !tcph->syn ) return;	

#ifdef DEBUG
		printf("fixmss ipv4 tcp syn\n");
#endif

		u_int8_t * opt = (u_int8_t *)tcph;
		for (i = sizeof(struct tcphdr); i < tcph->doff*4; i += optlen(opt, i)) {
			if (opt[i] == 2 && tcph->doff*4 - i >= 4 &&   // TCP_MSS
				opt[i+1] == 4 ) {
				u_int16_t newmss = 0, oldmss;
				if ( transfamily == PF_INET )
					newmss = 1418;
				else if ( transfamily == PF_INET6) 
					newmss = 1398;
				if (VLANdot1Q) newmss -=4;
				oldmss = (opt[i+2] << 8) | opt[i+3];
				/* Never increase MSS, even when setting it, as
			 	* doing so results in problems for hosts that rely
			 	* on MSS being set correctly.
				*/
				if (oldmss <= newmss)
					return;
#ifdef DEBUG
				printf("change inner v4 tcp mss from %d to %d\n",oldmss,newmss);
#endif
				opt[i+2] = (newmss & 0xff00) >> 8;
				opt[i+3] = newmss & 0x00ff;
			
				tcph->check = 0; /* Checksum field has to be set to 0 before checksumming */
				tcph->check = (u_int16_t) tcp_sum_calc((u_int16_t) (ntohs(ip->tot_len) - ip->ihl *4), (u_int16_t*) &ip->saddr, (u_int16_t*) &ip->daddr, (u_int16_t *) tcph); 
				return;
 			}
		}
		return;
	} else if( (packet[0] == 0x86) && (packet[1] == 0xdd) ) { // IPv6 packet, 0x86dd
		packet +=2;
		len -=2;

		struct ip6_hdr *ip6 = (struct ip6_hdr *) packet;
		if( (ip6->ip6_vfc&0xf0) != 0x60 ) return; // check ipv6
		if( ip6->ip6_nxt!= IPPROTO_TCP ) return; // not tcp packet
		if( ntohs(ip6->ip6_plen) > len ) return;  // tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr*) (packet + 40);
		if( !tcph->syn ) return;	
#ifdef DEBUG
		printf("fixmss ipv6 tcp syn\n");
#endif
		u_int8_t * opt = (u_int8_t *)tcph;
		for (i = sizeof(struct tcphdr); i < tcph->doff*4; i += optlen(opt, i)) {
			if (opt[i] == 2 && tcph->doff*4 - i >= 4 &&   // TCP_MSS
				opt[i+1] == 4 ) {
				u_int16_t newmss = 0, oldmss;
				if ( transfamily == PF_INET )
					newmss = 1398;
				else if ( transfamily == PF_INET6) 
					newmss = 1378;
				if (VLANdot1Q) newmss -=4;
				oldmss = (opt[i+2] << 8) | opt[i+3];
				/* Never increase MSS, even when setting it, as
			 	* doing so results in problems for hosts that rely
			 	* on MSS being set correctly.
				*/
				if (oldmss <= newmss)
					return;
#ifdef DEBUG
				printf("change inner v6 tcp mss from %d to %d\n",oldmss,newmss);
#endif

				opt[i+2] = (newmss & 0xff00) >> 8;
				opt[i+3] = newmss & 0x00ff;
			
				tcph->check = 0; /* Checksum field has to be set to 0 before checksumming */
				tcph->check = (u_int16_t) tcp_sum_calc_v6((u_int16_t) ntohs(ip6->ip6_plen), (u_int16_t*) &ip6->ip6_src, (u_int16_t*) &ip6->ip6_dst, (u_int16_t *) tcph); 
				return;
 			}
		}
		return;
	} else return; // not IP packet
}


void process_raw_to_udp( void)
{
  	u_int8_t buf[MAX_PACKET_SIZE];
	int len;

	while (1) { 	// read from eth rawsocket
		len = recv(fdraw, buf, MAX_PACKET_SIZE, 0);
		if( len <= 0 ) continue;
#ifdef FIXMSS
		fix_mss(buf, len);
#endif
#ifdef PRINTPKT
     		printPacket( (EtherPacket*) buf, len , "from local  rawsocket:");
#endif
		if ( nat ) {
#ifdef DEBUG
			printf("nat mode: send to port %d\n",ntohs(remote_addr.sin_port));
#endif
			if ( remote_addr.sin_port )
				sendto(fdudp, buf, len , 0, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in));
		} else
			write(fdudp, buf, len);
	}
}

void process_udp_to_raw( void)
{
  	u_int8_t buf[MAX_PACKET_SIZE];
	int len;

	while (1) { 	// read from remote udp
		if ( nat ) {
			struct sockaddr_in r;
			socklen_t sock_len = sizeof(struct sockaddr_in);
			len = recvfrom (fdudp, buf, MAX_PACKET_SIZE, 0, (struct sockaddr *)&r, &sock_len );
#ifdef DEBUG
			printf("nat mode: len %d recv from host %s\n",len,inet_ntoa(r.sin_addr));
			printf("remote_host is %s\n",inet_ntoa(remote_addr.sin_addr));
#endif
			if ( len <= 0 ) continue;
			if ( memcmp( (void*)&remote_addr.sin_addr, &r.sin_addr , 4 )==0) {
#ifdef DEBUG
				printf("nat mode: recv from port %d\n",ntohs(r.sin_port));
#endif
				remote_addr.sin_port = r.sin_port;
			}
		} else
			len = recv(fdudp, buf, MAX_PACKET_SIZE, 0);
		if( len <= 0 ) continue;
#ifdef FIXMSS
		fix_mss(buf, len);
#endif
#ifdef PRINTPKT
   		printPacket( (EtherPacket*) buf, len , "from remote udpsocket:");
#endif
  
		struct sockaddr_ll sll;
  		memset(&sll, 0, sizeof(sll));
  		sll.sll_family = AF_PACKET;
  		sll.sll_protocol = htons(ETH_P_ALL);
  		sll.sll_ifindex = ifindex;
  		sendto(fdraw, buf, len, 0, (struct sockaddr *)&sll, sizeof(sll));
	}
}

int main(int argc, char *argv[])
{
	pthread_t tid;
  	if(argc < 6) {
  		printf("Usage: ./EthUDP localip localport remoteip remoteport eth?\n");
  		exit(1);
  	}

#ifndef DEBUG
	daemon_init("EthUDP",LOG_DAEMON);
	while(1) {
   		int pid;
   		pid=fork();
   		if(pid==0) // child do the job
			break;
   		else if(pid==-1) // error
   			exit(0);
   		else
   			wait(NULL); // parent wait for child
   		sleep(2);  // wait 2 second, and rerun
   	}
#endif

	fdudp = udp_xconnect(argv[1], argv[2], argv[3], argv[4]);
	fdraw = open_socket(argv[5], &ifindex);
  	
	// create a pthread to forward packets from udp to raw
	if ( pthread_create(&tid, NULL, (void *)process_udp_to_raw, NULL)!=0)  {
                err_msg("pthread_create errno %d: %s\n",errno,strerror(errno));
                exit(0);
        }

	//  forward packets from raw to udp
        process_raw_to_udp();

        return 0;
}

