/* EthUDP: used to create transparent bridge over ipv4/ipv6 network
	  by james@ustc.edu.cn 2009.04.02


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
2. open udp socket to remote
3. if packet from raw socket, send to udp socket
4. if packet from udp socket, send to raw socket


*/	


// 0       6      12      12/16 14/18           18/22
// +-------+-------+---------+----+---------------+
// | DMAC  | SMAC  |8100 VLAN|Type|Payload (4Bfix)|
// +-------+-------+---------+----+---------------+


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h> 
#include <sys/ioctl.h>
#include <syslog.h> 
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <elf.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>

#define DEBUG		1

#define MAXLEN 2048
#define MAX_PACKET_SIZE	2048
#define MAXFD   64
#define NEWMSS 1400

#define max(a,b)        ((a) > (b) ? (a) : (b))
int             daemon_proc;            /* set nonzero by daemon_init() */

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

static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int	errno_save, n;
	char	buf[MAXLEN];

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
void
err_msg(const char *fmt, ...)
{
	va_list		ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void
err_quit(const char *fmt, ...)
{
	va_list		ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void
err_sys(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}


void
daemon_init(const char *pname, int facility)
{
        int    	i;
        pid_t   pid;

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

int
udp_server(const char *host, const char *serv, socklen_t *addrlenp)
{
        int	sockfd, n;
    	int	on=1;
        struct addrinfo hints, *res, *ressave;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) 
                err_quit("udp_server error for %s, %s", host, serv);
        ressave = res;

        do {
                sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (sockfd < 0)
                        continue;               /* error, try next one */
        	setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,1);
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

udp_xconnect(char *lhost,char*lserv,char*rhost,char*rserv)
{
        int	sockfd, n;
    	int    	on=1;
        struct addrinfo hints, *res, *ressave;
        sockfd=udp_server(lhost,lserv,NULL);
        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        if ( (n = getaddrinfo(rhost, rserv, &hints, &res)) != 0) 
                err_quit("udp_xconnect error for %s, %s",
                                 rhost, rserv);
        ressave = res;
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
 * Open a socket for the network interface
 */
int32_t open_socket(char *ifname, int32_t *rifindex) {
  unsigned char buf[MAX_PACKET_SIZE];
  int32_t i;
  int32_t ifindex;
  struct ifreq ifr;
  struct sockaddr_ll sll;

  int32_t fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd == -1) {
    printf("%s - ", ifname);
    perror("socket");
    _exit(1);
  };

  // get interface index
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
    printf("%s - ", ifname);
    perror("SIOCGIFINDEX");
    _exit(1);
  };
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
  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
    printf("%s - ", ifname);
    perror("bind");
    _exit(1);
  };

  /* flush all received packets. 
   *
   * raw-socket receives packets from all interfaces
   * when the socket is not bound to an interface
   */
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
    if (DEBUG) printf("interface %d flushed\n", ifindex);
  } while (i);

  if (DEBUG) printf("%s opened (fd=%d interface=%d)\n", ifname, fd, ifindex);

  return fd;
}


void printPacket(EtherPacket *packet, ssize_t packetSize, char *message) 
{
        if ( ntohl(packet->VLANTag) >> 16 == 0x8100 )  // VLAN tag
                printf("%s #%04x (VLAN %d) from %04x%08x to %04x%08x, len=%d\n",
                        message, ntohs(packet->type), ntohl(packet->VLANTag) & 0xFFF,
                        ntohs(packet->srcMAC1), ntohl(packet->srcMAC2),
                        ntohs(packet->destMAC1), ntohl(packet->destMAC2), packetSize);
        else
                printf("%s #%04x (no VLAN) from %04x%08x to %04x%08x, len=%d\n",
                        message, ntohl(packet->VLANTag) >> 16,
                        ntohs(packet->srcMAC1), ntohl(packet->srcMAC2),
                        ntohs(packet->destMAC1), ntohl(packet->destMAC2), packetSize);
}

// function from http://www.bloof.de/tcp_checksumming, thanks to crunsh
unsigned short tcp_sum_calc(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], unsigned short buff[])
{
    unsigned char prot_tcp=6;
    unsigned long sum;
    int nleft;
    unsigned short *w;
 
    sum = 0;
    nleft = len_tcp;
    w=buff;
 
    /* calculate the checksum for the tcp header and payload */
    while(nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
 
    /* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
    if(nleft>0)
    {
    	/* sum += *w&0xFF; */
             sum += *w&ntohs(0xFF00);   /* Thanks to Dalton */
    }
 
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
 
    return ((unsigned short) sum);
}

static unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
		return 1;
	else
		return opt[offset+1];
}

void fix_mss(char *buf, int len)
{
	u_int8_t * packet;
	int i;

	int newmss = NEWMSS;

	if( len < 54 ) return;
	packet = buf +12; // skip ethernet dst & src addr
	len -=12;

	if( (packet[0] == 0x81) && (packet[1] == 0x00) ) { // skip 802.1Q tag
		packet +=2;
		len -=2;
	}
	if( (packet[0] == 0x08) && (packet[1] == 0x00) ) { // IP packet 
		packet +=2;
		len -=2;
	} else return; // not IP packet
	
	struct iphdr *ip = (struct iphdr *) packet;

	if( ip->version !=4 ) return; // only support ipv4
	if( ip->frag_off & 0x1fff ) return;  // not the first fragment
	if( ip->protocol != IPPROTO_TCP ) return; // not tcp packet
	if( ntohs(ip->tot_len) > len ) return;  // tot_len ??

	struct tcphdr *tcph = (struct tcphdr*) packet + ip->ihl *4;

	if( !tcph->syn ) return;	
	char * opt = (u_int8_t *)tcph;
	for (i = sizeof(struct tcphdr); i < tcph->doff*4; i += optlen(opt, i)) {
		if (opt[i] == 2 && tcph->doff*4 - i >= 4 &&   // TCP_MSS
			opt[i+1] == 4 ) {
			u_int16_t oldmss;
			oldmss = (opt[i+2] << 8) | opt[i+3];
			/* Never increase MSS, even when setting it, as
			 * doing so results in problems for hosts that rely
			 * on MSS being set correctly.
			*/
			if (oldmss <= newmss)
				return;
			if(DEBUG) printf("change mss from %d to %d\n",oldmss,newmss);
			opt[i+2] = (newmss & 0xff00) >> 8;
			opt[i+3] = newmss & 0x00ff;
		
			tcph->check = 0; /* Checksum field has to be set to 0 before checksumming */
			tcph->check = (unsigned short) tcp_sum_calc((unsigned short) (ip->tot_len - ip->ihl *4), (unsigned short *) &ip->saddr, (unsigned short *) &ip->daddr, (unsigned short *) &tcph); 
			return;
 		}
	}
}

int main(int argc, char *argv[])
{
  	int32_t ifindex;
	int fdudp, fdraw;

  	if(argc < 6) {
  		printf("Usage: ./EthUDP localip localport remoteip remoteport eth?");
  		exit(1);
  	}

if (!DEBUG) {
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

}
	fdudp = udp_xconnect(argv[1],argv[2],argv[3],argv[4]);
	fdraw = open_socket(argv[5], &ifindex);
  	
// Set non-blocking mode:
 	int32_t flags = fcntl(fdraw, F_GETFL, 0);
  	fcntl(fdraw, F_SETFL, O_NONBLOCK | flags);
 	flags = fcntl(fdudp, F_GETFL, 0);
  	fcntl(fdudp, F_SETFL, O_NONBLOCK | flags);


	while(1){
  		char buf[MAX_PACKET_SIZE];
  		fd_set fds;
		int l;

		FD_ZERO(&fds);
		FD_SET(fdudp, &fds);
		FD_SET(fdraw , &fds);
			
		select(max(fdudp, fdraw)+1, &fds, NULL, NULL, NULL);

		if( FD_ISSET(fdraw, &fds) ) {  // read from eth rawsocket
			l = recv(fdraw, buf, MAX_PACKET_SIZE, 0);
			if(DEBUG) printf("%d bytes from eth rawsocket\n",l);
			if(l<=0) continue;
			fix_mss(buf,l);
			if(DEBUG) {
   	   			EtherPacket *packet = (EtherPacket*) buf;
      				printPacket(packet, l , "Received:");
			}
			l = write(fdudp,buf,l);
			if(DEBUG) printf("%d bytes write to udp\n",l);
		}  
		if( FD_ISSET(fdudp, &fds) ) {  // read from remote udp
			l = read(fdudp,buf,sizeof(buf));
			if(DEBUG) printf("%d bytes from udp socket\n",l);
			if(l<=0) continue;
			fix_mss(buf,l);
			if(DEBUG) {
   	   			EtherPacket *packet = (EtherPacket*) buf;
      				printPacket(packet, l , "Received:");
			}
  
			struct sockaddr_ll sll;
  			memset(&sll, 0, sizeof(sll));
  			sll.sll_family = AF_PACKET;
  			sll.sll_protocol = htons(ETH_P_ALL);	// Ethernet type = Trans. Ether Bridging
  			sll.sll_ifindex = ifindex;
  			l = sendto(fdraw, buf, l, 0, (struct sockaddr *)&sll, sizeof(sll));
			if(DEBUG) printf("%d bytes write to rawsocket\n",l);
		}
	}
}
