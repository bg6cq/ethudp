/* EthUDP: used to create tunnel over ipv4/ipv6 network
	  by james@ustc.edu.cn 2009.04.02
*/

// kernel use auxdata to send vlan tag, we use auxdata to reconstructe vlan header
#define HAVE_PACKET_AUXDATA 1

// enable OPENSSL encrypt/decrypt support
#define ENABLE_OPENSSL 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <lz4.h>
#include <pcap.h>

#define MAXLEN 			2048
#define MAX_PACKET_SIZE		9234	// Jumbo Frame
#define MAXFD   		64

#define STATUS_BAD 	0
#define STATUS_OK  	1
#define MASTER 		0
#define SLAVE 		1

#define MODEE	0		// raw ether bridge mode
#define MODEI	1		// tap interface mode
#define MODEB	2		// bridge mode
#define MODET	3		// tcpdump

//#define DEBUGPINGPONG 1
//#define DEBUGSSL      1

// ip & brctl command
#define IPCMD 		"/sbin/ip"
#define BRIDGECMD	"/usr/sbin/brctl"

#define XOR 	1

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#define AES_128 2
#define AES_192 3
#define AES_256 3
#else
#define EVP_MAX_BLOCK_LENGTH 0
#endif

#define max(a,b)        ((a) > (b) ? (a) : (b))

#ifdef HAVE_PACKET_AUXDATA
#define VLAN_TAG_LEN   4
struct vlan_tag {
	u_int16_t vlan_tpid;	/* ETH_P_8021Q */
	u_int16_t vlan_tci;	/* VLAN TCI */
};
#endif

u_int16_t ETHP8021Q;		// 0x8100 in network order

struct _EtherHeader {
	uint16_t destMAC1;
	uint32_t destMAC2;
	uint16_t srcMAC1;
	uint32_t srcMAC2;
	uint32_t VLANTag;
	uint16_t type;
	int32_t payload;
} __attribute__ ((packed));

typedef struct _EtherHeader EtherPacket;

struct packet_buf {
	time_t rcvt;		// recv time, 0 if not valid
	int len;		// buf len
	unsigned char *buf;	// packet header is 8 bytes: UDPFRG+seq
};

#define MAXPKTS 65536

struct packet_buf packet_bufs[MAXPKTS];	// buf[0] & buf[1] is pair, store the orignal big UDP packets

int daemon_proc;		/* set nonzero by daemon_init() */
volatile int debug = 0;

int mode = -1;			// 0 eth bridge, 1 interface, 2 bridge
int mtu = 0;
int udp_frg_seq = 0;
int master_slave = 0;
int read_only = 0, write_only = 0;
int fixmss = 0;
int nopromisc = 0;
int loopback_check = 0;
int packet_len = 1500;
char name[MAXLEN];
char run_cmd[MAXLEN];
char dev_name[MAXLEN];
int run_seconds = 0;

int32_t ifindex;

char mypassword[MAXLEN];
int enc_algorithm;
unsigned char enc_key[MAXLEN];
#ifdef ENABLE_OPENSSL
unsigned char enc_iv[EVP_MAX_IV_LENGTH];
#endif
int enc_key_len = 0;

int fdudp[2], fdraw;
int nat[2];
pcap_t *pcap_handle;

int lz4 = 0;
volatile long long udp_total = 0;
volatile long long compress_overhead = 0;
volatile long long compress_save = 0;
volatile long long encrypt_overhead = 0;
#define LZ4_SPACE 128

int vlan_map = 0;
int my_vlan[4096];
int remote_vlan[4096];

volatile struct sockaddr_storage local_addr[2];
volatile struct sockaddr_storage cmd_remote_addr[2];
volatile struct sockaddr_storage remote_addr[2];
volatile unsigned long myticket, last_pong[2];	// myticket inc 1 every 1 second after start
volatile unsigned long ping_send[2], ping_recv[2], pong_send[2], pong_recv[2];
volatile unsigned long raw_send_pkt, raw_send_byte, raw_recv_pkt, raw_recv_byte;
volatile unsigned long udp_send_pkt[2], udp_send_byte[2], udp_recv_pkt[2], udp_recv_byte[2];
volatile unsigned long udp_send_err[2], raw_send_err;
volatile int master_status = STATUS_BAD;
volatile int slave_status = STATUS_BAD;
volatile int current_remote = MASTER;
volatile int got_signal = 1;

void sig_handler_hup(int signo)
{
	got_signal = 1;
}

void sig_handler_usr1(int signo)
{
	udp_total = compress_overhead = compress_save = encrypt_overhead = 0;
	raw_send_pkt = raw_send_byte = raw_recv_pkt = raw_recv_byte = 0;
	udp_send_pkt[0] = udp_send_byte[0] = udp_recv_pkt[0] = udp_recv_byte[0] = 0;
	udp_send_pkt[1] = udp_send_byte[1] = udp_recv_pkt[1] = udp_recv_byte[1] = 0;
}

void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLEN];

	errno_save = errno;	/* value caller might want printed */
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		if (name[0])
			syslog(level, "%s: %s", name, buf);
		else
			syslog(level, "%s", buf);
	} else {
		fflush(stdout);	/* in case stdout and stderr are the same */
		if (name[0]) {
			fputs(name, stderr);
			fputs(": ", stderr);
		}
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

void err_msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void Debug(const char *fmt, ...)
{
	va_list ap;
	if (debug) {
		va_start(ap, fmt);
		err_doit(0, LOG_INFO, fmt, ap);
		va_end(ap);
	}
	return;
}

void err_quit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void daemon_init(const char *pname, int facility)
{
	int i;
	pid_t pid;
	if ((pid = fork()) != 0)
		exit(0);	/* parent terminates */

	/* 41st child continues */
	setsid();		/* become session leader */

	signal(SIGHUP, SIG_IGN);
	if ((pid = fork()) != 0)
		exit(0);	/* 1st child terminates */

	/* 42nd child continues */
	daemon_proc = 1;	/* for our err_XXX() functions */

	umask(0);		/* clear our file mode creation mask */

	for (i = 0; i < MAXFD; i++)
		close(i);

	openlog(pname, LOG_PID, facility);
}

int udp_server(const char *host, const char *serv, socklen_t * addrlenp, int index)
{
	int sockfd, n;
	int on = 1;
	struct addrinfo hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		err_quit("udp_server error for %s, %s", host, serv);
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;	/* error, try next one */
		memcpy((void *)&(local_addr[index]), res->ai_addr, res->ai_addrlen);
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, 1);
		if (bind(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;	/* success */
		close(sockfd);	/* bind error, close and try next one */
	}
	while ((res = res->ai_next) != NULL);

	if (res == NULL)	/* errno from final socket() or bind() */
		err_sys("udp_server error for %s, %s", host, serv);

	if (addrlenp)
		*addrlenp = res->ai_addrlen;	/* return size of protocol address */

	freeaddrinfo(ressave);

	return (sockfd);
}

int udp_xconnect(char *lhost, char *lserv, char *rhost, char *rserv, int index)
{
	int sockfd, n;
	struct addrinfo hints, *res, *ressave;

	sockfd = udp_server(lhost, lserv, NULL, index);

	n = 10 * 1024 * 1024;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
	if (debug) {
		socklen_t ln;
		if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0)
			Debug("UDP socket RCVBUF setting to %d\n", n);
	}
// set IP_MTU_DISCOVER, otherwise UDP has DFbit set
	n = 0;
	if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &n, sizeof(n)) != 0)
		err_msg("udp_xeonnect setsockopt returned error, errno %d\n", errno);

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((n = getaddrinfo(rhost, rserv, &hints, &res)) != 0)
		err_quit("udp_xconnect error for %s, %s", rhost, rserv);
	ressave = res;

	do {
		void *raddr;
		if (res->ai_family == AF_INET) {	// IPv4
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
			raddr = &(ipv4->sin_addr);
			if ((memcmp(raddr, "\0\0\0\0", 4) == 0) || (ipv4->sin_port == 0)) {
				Debug("nat = 1");
				nat[index] = 1;
				memcpy((void *)&(cmd_remote_addr[index]), res->ai_addr, res->ai_addrlen);
				freeaddrinfo(ressave);
				return sockfd;
			}
		} else {	// IPv6
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
			raddr = &(ipv6->sin6_addr);
			if ((memcmp(raddr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0) || (ipv6->sin6_port == 0)) {
				Debug("nat = 1");
				nat[index] = 1;
				memcpy((void *)&(cmd_remote_addr[index]), res->ai_addr, res->ai_addrlen);
				freeaddrinfo(ressave);
				return sockfd;
			}
		}

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
			memcpy((void *)&(cmd_remote_addr[index]), res->ai_addr, res->ai_addrlen);
			memcpy((void *)&(remote_addr[index]), res->ai_addr, res->ai_addrlen);
			break;	/* success */
		}
	}
	while ((res = res->ai_next) != NULL);

	if (res == NULL)	/* errno set from final connect() */
		err_sys("udp_xconnect error for %s, %s", rhost, rserv);

	freeaddrinfo(ressave);

	return (sockfd);
}

/**
 * Open a rawsocket for the network interface
 */
int32_t open_rawsocket(char *ifname, int32_t * rifindex)
{
	unsigned char buf[MAX_PACKET_SIZE];
	int32_t ifindex;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	int n;

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

	if (!nopromisc) {	// set promiscuous mode
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		ioctl(fd, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags |= IFF_PROMISC;
		ioctl(fd, SIOCSIFFLAGS, &ifr);
	}

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
	int32_t i, l = 0;
	do {
		fd_set fds;
		struct timeval t;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		memset(&t, 0, sizeof(t));
		i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
		if (i > 0) {
			recv(fd, buf, i, 0);
			l++;
		};
		Debug("interface %d flushed %d packets", ifindex, l);
	}
	while (i > 0);

	/* Enable auxillary data if supported and reserve room for
	 * reconstructing VLAN headers. */
#ifdef HAVE_PACKET_AUXDATA
	int val = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) == -1 && errno != ENOPROTOOPT) {
		err_sys("setsockopt(packet_auxdata): %s", strerror(errno));
	}
#endif				/* HAVE_PACKET_AUXDATA */

	Debug("%s opened (fd=%d interface=%d)", ifname, fd, ifindex);

	n = 10 * 1024 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
	if (debug) {
		socklen_t ln;
		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0) {
			Debug("RAW socket RCVBUF setting to %d", n);
		}
	}

	return fd;
}

int xor_encrypt(u_int8_t * buf, int n, u_int8_t * nbuf)
{
	int i;
	for (i = 0; i < n; i++)
		nbuf[i] = buf[i] ^ enc_key[i % enc_key_len];
	return n;
}

#ifdef ENABLE_OPENSSL
int openssl_encrypt(u_int8_t * buf, int len, u_int8_t * nbuf)
{
	EVP_CIPHER_CTX *ctx;
	int outlen1, outlen2;
#ifdef DEBUGSSL
	Debug("aes encrypt len=%d", len);
#endif
	ctx = EVP_CIPHER_CTX_new();
	if (enc_algorithm == AES_128)
		EVP_EncryptInit(ctx, EVP_aes_128_cbc(), enc_key, enc_iv);
	else if (enc_algorithm == AES_192)
		EVP_EncryptInit(ctx, EVP_aes_192_cbc(), enc_key, enc_iv);
	else if (enc_algorithm == AES_256)
		EVP_EncryptInit(ctx, EVP_aes_256_cbc(), enc_key, enc_iv);
	EVP_EncryptUpdate(ctx, nbuf, &outlen1, buf, len);
	EVP_EncryptFinal(ctx, nbuf + outlen1, &outlen2);
	len = outlen1 + outlen2;

#ifdef DEBUGSSL
	Debug("after aes encrypt len=%d", len);
#endif
	EVP_CIPHER_CTX_free(ctx);
	return len;
}

int openssl_decrypt(u_int8_t * buf, int len, u_int8_t * nbuf)
{

	EVP_CIPHER_CTX *ctx;
	int outlen1, outlen2;
#ifdef DEBUGSSL
	Debug("aes decrypt len=%d", len);
#endif
	ctx = EVP_CIPHER_CTX_new();
	if (enc_algorithm == AES_128)
		EVP_DecryptInit(ctx, EVP_aes_128_cbc(), enc_key, enc_iv);
	else if (enc_algorithm == AES_192)
		EVP_DecryptInit(ctx, EVP_aes_192_cbc(), enc_key, enc_iv);
	else if (enc_algorithm == AES_256)
		EVP_DecryptInit(ctx, EVP_aes_256_cbc(), enc_key, enc_iv);
	if (EVP_DecryptUpdate(ctx, nbuf, &outlen1, buf, len) != 1 || EVP_DecryptFinal(ctx, nbuf + outlen1, &outlen2) != 1)
		len = 0;
	else
		len = outlen1 + outlen2;
#ifdef DEBUGSSL
	Debug("after aes decrypt len=%d", len);
#endif
	EVP_CIPHER_CTX_free(ctx);
	return len;
}
#endif

int do_encrypt(u_int8_t * buf, int len, u_int8_t * nbuf)
{
	u_int8_t lzbuf[MAX_PACKET_SIZE + LZ4_SPACE];
	int nlen;
	udp_total += len;
	if (lz4 > 0) {
		nlen = LZ4_compress_fast((char *)buf, (char *)lzbuf, len, len + LZ4_SPACE, lz4);
		if (nlen <= 0) {
			err_msg("lz4 compress error");
			return 0;
		}
		if (debug)
			Debug("compress %d-->%d save %d byte", len, nlen, len - nlen);
		if (nlen < len) {	// compressed 
			lzbuf[nlen] = 0xff;	// 0xff means compressed data
			nlen++;
			compress_save += len - nlen;
			len = nlen;
			buf = lzbuf;
		} else {
			buf[len] = 0xaa;	// 0xaa means not compressed data
			compress_overhead++;
			len++;
			if (debug)
				Debug("not compressed %d", len);
		}
	}
	if (enc_key_len <= 0) {
		memcpy(nbuf, buf, len);
		return len;
	}
	if (enc_algorithm == XOR)
		nlen = xor_encrypt(buf, len, nbuf);
#ifdef ENABLE_OPENSSL
	else if ((enc_algorithm == AES_128)
		 || (enc_algorithm == AES_192)
		 || (enc_algorithm == AES_256))
		nlen = openssl_encrypt(buf, len, nbuf);
#endif
	else
		return 0;
	if (debug)
		Debug("encrypt_overhead %d", nlen - len);
	encrypt_overhead += nlen - len;
	return nlen;
}

int do_decrypt(u_int8_t * buf, int len, u_int8_t * nbuf)
{
	u_int8_t lzbuf[MAX_PACKET_SIZE + LZ4_SPACE];
	if (enc_key_len > 0) {
		if (enc_algorithm == XOR) {
			len = xor_encrypt(buf, len, lzbuf);
			buf = lzbuf;
		}
#ifdef ENABLE_OPENSSL
		else if ((enc_algorithm == AES_128)
			 || (enc_algorithm == AES_192)
			 || (enc_algorithm == AES_256)) {
			len = openssl_decrypt(buf, len, lzbuf);
			buf = lzbuf;
		}
#endif
	}
	if ((lz4 > 0) && (len > 0)) {
		len--;
		if (buf[len] == 0xaa) {	// not compressed data
			if (debug)
				Debug("decompress not compressed data %d", len);
			memcpy(nbuf, buf, len);
		} else if (buf[len] == 0xff) {	// compressed data
			int nlen;
			nlen = LZ4_decompress_safe((char *)buf, (char *)nbuf, len, MAX_PACKET_SIZE + LZ4_SPACE);
			if (nlen < 0) {
				err_msg("lz4 decompress error");
				return 0;
			}
			if (debug)
				Debug("decompress %d-->%d", len, nlen);
			len = nlen;
		} else {
			err_msg("len %d last byte error 0x%02X", len, buf[len]);
			return 0;
		}
	} else
		memcpy(nbuf, buf, len);
	return len;
}

char *stamp(void)
{
	static char st_buf[200];
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;

	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);

	snprintf(st_buf, 200, "%02d%02d %02d:%02d:%02d.%06ld", tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
	return st_buf;
}

void printPacket(EtherPacket * packet, ssize_t packetSize, char *message)
{
	printf("%s ", stamp());

	if ((ntohl(packet->VLANTag) >> 16) == 0x8100)	// VLAN tag
		printf("%s #%04x (VLAN %d) from %04x%08x to %04x%08x, len=%d\n",
		       message, ntohs(packet->type),
		       ntohl(packet->VLANTag) & 0xFFF, ntohs(packet->srcMAC1),
		       ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	else
		printf("%s #%04x (no VLAN) from %04x%08x to %04x%08x, len=%d\n",
		       message, ntohl(packet->VLANTag) >> 16,
		       ntohs(packet->srcMAC1), ntohl(packet->srcMAC2), ntohs(packet->destMAC1), ntohl(packet->destMAC2), (int)packetSize);
	fflush(stdout);
}

// function from http://www.bloof.de/tcp_checksumming, thanks to crunsh
u_int16_t tcp_sum_calc(u_int16_t len_tcp, u_int16_t src_addr[], u_int16_t dest_addr[], u_int16_t buff[])
{
	u_int16_t prot_tcp = 6;
	u_int32_t sum = 0;
	int nleft = len_tcp;
	u_int16_t *w = buff;

	/* calculate the checksum for the tcp header and payload */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
	if (nleft > 0)
		sum += *w & ntohs(0xFF00);	/* Thanks to Dalton */

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

u_int16_t tcp_sum_calc_v6(u_int16_t len_tcp, u_int16_t src_addr[], u_int16_t dest_addr[], u_int16_t buff[])
{
	u_int16_t prot_tcp = 6;
	u_int32_t sum = 0;
	int nleft = len_tcp;
	u_int16_t *w = buff;

	/* calculate the checksum for the tcp header and payload */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* if nleft is 1 there ist still on byte left. We add a padding byte (0xFF) to build a 16bit word */
	if (nleft > 0)
		sum += *w & ntohs(0xFF00);	/* Thanks to Dalton */

	/* add the pseudo header */
	int i;
	for (i = 0; i < 8; i++)
		sum = sum + src_addr[i] + dest_addr[i];

	sum += htons(len_tcp);	// why using 32bit len_tcp
	sum += htons(prot_tcp);

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	return ((u_int16_t) sum);
}

static unsigned int optlen(const u_int8_t * opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset + 1] == 0)
		return 1;
	else
		return opt[offset + 1];
}

void fix_mss(u_int8_t * buf, int len, int index)
{
	u_int8_t *packet;
	int i;

	if (len < 54)
		return;
	packet = buf + 12;	// skip ethernet dst & src addr
	len -= 12;

	if ((packet[0] == 0x81) && (packet[1] == 0x00)) {	// skip 802.1Q tag 0x8100
		packet += 4;
		len -= 4;
	}
	if ((packet[0] == 0x08) && (packet[1] == 0x00)) {	// IPv4 packet 0x0800
		packet += 2;
		len -= 2;

		struct iphdr *ip = (struct iphdr *)packet;
		if (ip->version != 4)
			return;	// check ipv4
		if (ntohs(ip->frag_off) & 0x1fff)
			return;	// not the first fragment
		if (ip->protocol != IPPROTO_TCP)
			return;	// not tcp packet
		if (ntohs(ip->tot_len) > len)
			return;	// tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr *)(packet + ip->ihl * 4);
		if (!tcph->syn)
			return;

		if (debug)
			Debug("fixmss ipv4 tcp syn");

		u_int8_t *opt = (u_int8_t *) tcph;
		for (i = sizeof(struct tcphdr); i < tcph->doff * 4; i += optlen(opt, i)) {
			if (opt[i] == 2 && tcph->doff * 4 - i >= 4 &&	// TCP_MSS
			    opt[i + 1] == 4) {
				u_int16_t newmss = fixmss, oldmss;
				oldmss = (opt[i + 2] << 8) | opt[i + 3];
				/* Never increase MSS, even when setting it, as
				 * doing so results in problems for hosts that rely
				 * on MSS being set correctly.
				 */
				if (oldmss <= newmss)
					return;
				if (debug)
					Debug("change inner v4 tcp mss from %d to %d", oldmss, newmss);
				opt[i + 2] = (newmss & 0xff00) >> 8;
				opt[i + 3] = newmss & 0x00ff;

				tcph->check = 0;	/* Checksum field has to be set to 0 before checksumming */
				tcph->check = (u_int16_t)
				    tcp_sum_calc((u_int16_t)
						 (ntohs(ip->tot_len) - ip->ihl * 4), (u_int16_t *) & ip->saddr, (u_int16_t *) & ip->daddr, (u_int16_t *) tcph);
				return;
			}
		}
	} else if ((packet[0] == 0x86) && (packet[1] == 0xdd)) {	// IPv6 packet, 0x86dd
		packet += 2;
		len -= 2;

		struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
		if ((ip6->ip6_vfc & 0xf0) != 0x60)
			return;	// check ipv6
		if (ip6->ip6_nxt != IPPROTO_TCP)
			return;	// not tcp packet
		if (ntohs(ip6->ip6_plen) > len)
			return;	// tot_len should < len 

		struct tcphdr *tcph = (struct tcphdr *)(packet + 40);
		if (!tcph->syn)
			return;
		if (debug)
			Debug("fixmss ipv6 tcp syn");
		u_int8_t *opt = (u_int8_t *) tcph;
		for (i = sizeof(struct tcphdr); i < tcph->doff * 4; i += optlen(opt, i)) {
			if (opt[i] == 2 && tcph->doff * 4 - i >= 4 &&	// TCP_MSS
			    opt[i + 1] == 4) {
				u_int16_t newmss = fixmss, oldmss;
				oldmss = (opt[i + 2] << 8) | opt[i + 3];
				/* Never increase MSS, even when setting it, as
				 * doing so results in problems for hosts that rely
				 * on MSS being set correctly.
				 */
				if (oldmss <= newmss)
					return;
				if (debug)
					Debug("change inner v6 tcp mss from %d to %d", oldmss, newmss);

				opt[i + 2] = (newmss & 0xff00) >> 8;
				opt[i + 3] = newmss & 0x00ff;

				tcph->check = 0;	/* Checksum field has to be set to 0 before checksumming */
				tcph->check = (u_int16_t) tcp_sum_calc_v6((u_int16_t)
									  ntohs(ip6->ip6_plen),
									  (u_int16_t *) & ip6->ip6_src, (u_int16_t *) & ip6->ip6_dst, (u_int16_t *)
									  tcph);
				return;
			}
		}
	}
}

/*  return 1 if packet will cause loopback, DSTIP or SRCIP == remote address && PROTO == UDP
*/
int do_loopback_check(u_int8_t * buf, int len)
{
	u_int8_t *packet;

	if (len < 14)		// MAC(12)+Proto(2)+IP(20)
		return 0;
	packet = buf + 12;	// skip ethernet dst & src addr
	len -= 12;

	if ((packet[0] == 0x81) && (packet[1] == 0x00)) {	// skip 802.1Q tag 0x8100
		packet += 4;
		len -= 4;
	}
	if ((packet[0] == 0x08) && (packet[1] == 0x00)) {	// IPv4 packet 0x0800
		packet += 2;
		len -= 2;

		if (len < 20)	// IP header len is 20
			return 0;

		struct iphdr *ip = (struct iphdr *)packet;
		if (ip->version != 4)
			return 0;	// not ipv4
		if (ip->protocol != IPPROTO_UDP)
			return 0;	// not udp packet

		struct sockaddr_in *r = (struct sockaddr_in *)(&remote_addr[MASTER]);
		if (ip->saddr == r->sin_addr.s_addr) {
			if (debug)
				Debug("master remote ipaddr == src addr, loopback");
			return 1;
		} else if (ip->daddr == r->sin_addr.s_addr) {
			if (debug)
				Debug("master remote ipaddr == dst addr, loopback");
			return 1;
		}
		if (master_slave) {
			r = (struct sockaddr_in *)(&remote_addr[SLAVE]);
			if (ip->saddr == r->sin_addr.s_addr) {
				if (debug)
					Debug("slave remote ipaddr == src addr, loopback");
				return 1;
			} else if (ip->daddr == r->sin_addr.s_addr) {
				if (debug)
					Debug("slave remote ipaddr == dst addr, loopback");
				return 1;
			}
		}
	} else if ((packet[0] == 0x86) && (packet[1] == 0xdd)) {	// IPv6 packet, 0x86dd
		packet += 2;
		len -= 2;

		if (len < 40)	// IPv6 header len is 40
			return 0;

		struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
		if ((ip6->ip6_vfc & 0xf0) != 0x60)
			return 0;	// not ipv6
		if (ip6->ip6_nxt != IPPROTO_UDP)
			return 0;	// not udp packet

		struct sockaddr_in6 *r = (struct sockaddr_in6 *)&remote_addr[MASTER];
		if (memcmp(&ip6->ip6_src, &r->sin6_addr, 16) == 0) {
			if (debug)
				Debug("master remote ip6_addr == src ip6 addr, loopback");
			return 1;
		} else if (memcmp(&ip6->ip6_dst, &r->sin6_addr, 16) == 0) {
			if (debug)
				Debug("master remote ip6_addr == dst ip6 addr, loopback");
			return 1;
		}
		if (master_slave) {
			r = (struct sockaddr_in6 *)&remote_addr[SLAVE];
			if (memcmp(&ip6->ip6_src, &r->sin6_addr, 16) == 0) {
				if (debug)
					Debug("slave remote ip6_addr == src ip6 addr, loopback");
				return 1;
			} else if (memcmp(&ip6->ip6_dst, &r->sin6_addr, 16) == 0) {
				if (debug)
					Debug("slave remote ip6_addr == dst ip6 addr, loopback");
				return 1;
			}
		}
	}
	return 0;
}

void send_udp_to_remote(u_int8_t * buf, int len, int index);

void send_frag_udp(u_int8_t * buf, int len, int index)
{
	unsigned char newbuf[MAX_PACKET_SIZE];
	if (len >= 2000)	// should not go here
		return;
	if (len <= 1000)	// should not go here
		return;
	memcpy(newbuf, "UDPFRG", 6);
	newbuf[6] = (udp_frg_seq >> 8) & 0xff;
	newbuf[7] = udp_frg_seq & 0xff;
	memcpy(newbuf + 8, buf, 1000);
	if (debug)
		Debug("send frag %d, len=1000, total_len=%d", udp_frg_seq, len);
	send_udp_to_remote(newbuf, 1008, index);
	udp_frg_seq++;
	if (udp_frg_seq >= MAXPKTS)
		udp_frg_seq = 0;
	newbuf[6] = (udp_frg_seq >> 8) & 0xff;
	newbuf[7] = udp_frg_seq & 0xff;
	memcpy(newbuf + 8, buf + 1000, len - 1000);
	if (debug)
		Debug("send frag %d, len=%d, total_len=%d", udp_frg_seq, len - 1000, len);
	send_udp_to_remote(newbuf, 8 + len - 1000, index);
	udp_frg_seq++;
	if (udp_frg_seq >= MAXPKTS)
		udp_frg_seq = 0;
}

void send_udp_to_remote(u_int8_t * buf, int len, int index)	// send udp packet to remote 
{
	if ((mtu > 0) && (len > mtu - 28))
		return send_frag_udp(buf, len, index);
	if (nat[index]) {
		char rip[200];
		if (remote_addr[index].ss_family == AF_INET) {
			struct sockaddr_in *r = (struct sockaddr_in *)(&remote_addr[index]);
			if (debug)
				Debug("nat mode: send len %d to %s:%d", len, inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), ntohs(r->sin_port));
			if (r->sin_port) {
				sendto(fdudp[index], buf, len, 0, (struct sockaddr *)&remote_addr[index], sizeof(struct sockaddr_storage));
				udp_send_pkt[index]++;
				udp_send_byte[index] += len;
			}
		} else if (remote_addr[index].ss_family == AF_INET6) {
			struct sockaddr_in6 *r = (struct sockaddr_in6 *)&remote_addr[index];
			if (debug)
				Debug("nat mode: send len %d to [%s]:%d", len, inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), ntohs(r->sin6_port));
			if (r->sin6_port) {
				sendto(fdudp[index], buf, len, 0, (struct sockaddr *)&remote_addr[index], sizeof(struct sockaddr_storage));
				udp_send_pkt[index]++;
				udp_send_byte[index] += len;
			}
		}
	} else {
		if (write(fdudp[index], buf, len) != len)
			udp_send_err[index]++;
		else {
			udp_send_pkt[index]++;
			udp_send_byte[index] += len;
		}
	}
}

void print_addrinfo(int index)
{
	char localip[200];
	char cmd_remoteip[200];
	char remoteip[200];
	if (local_addr[index].ss_family == AF_INET) {
		struct sockaddr_in *r = (struct sockaddr_in *)(&local_addr[index]);
		int lp, c_rp, rp;
		lp = ntohs(r->sin_port);
		inet_ntop(AF_INET, &r->sin_addr, localip, 200);
		r = (struct sockaddr_in *)(&cmd_remote_addr[index]);
		c_rp = ntohs(r->sin_port);
		inet_ntop(AF_INET, &r->sin_addr, cmd_remoteip, 200);
		r = (struct sockaddr_in *)(&remote_addr[index]);
		rp = ntohs(r->sin_port);
		inet_ntop(AF_INET, &r->sin_addr, remoteip, 200);
		if (nat[index])
			err_msg("%s: ST:%d %s:%d --> %s:%d(%s:%d)", index == 0 ? "MASTER" : " SLAVE", index == 0 ? master_status : slave_status, localip, lp,
				remoteip, rp, cmd_remoteip, c_rp);
		else
			err_msg("%s: ST:%d %s:%d --> %s:%d", index == 0 ? "MASTER" : " SLAVE", index == 0 ? master_status : slave_status, localip, lp, remoteip,
				rp);
	} else if (local_addr[index].ss_family == AF_INET6) {
		struct sockaddr_in6 *r = (struct sockaddr_in6 *)(&local_addr[index]);
		int lp, c_rp, rp;
		lp = ntohs(r->sin6_port);
		inet_ntop(AF_INET6, &r->sin6_addr, localip, 200);
		r = (struct sockaddr_in6 *)(&cmd_remote_addr[index]);
		c_rp = ntohs(r->sin6_port);
		inet_ntop(AF_INET6, &r->sin6_addr, cmd_remoteip, 200);
		r = (struct sockaddr_in6 *)(&remote_addr[index]);
		rp = ntohs(r->sin6_port);
		inet_ntop(AF_INET6, &r->sin6_addr, remoteip, 200);
		if (nat[index])
			err_msg("%s: ST:%d [%s]:%d --> [%s]:%d([%s]:%d)", index == 0 ? "MASTER" : " SLAVE", index == 0 ? master_status : slave_status, localip,
				lp, remoteip, rp, cmd_remoteip, c_rp);
		else
			err_msg("%s: ST:%d [%s]:%d --> [%s]:%d", index == 0 ? "MASTER" : " SLAVE", index == 0 ? master_status : slave_status, localip, lp,
				remoteip, rp);
	}
}

void send_keepalive_to_udp(void)	// send keepalive to remote  
{
	u_int8_t buf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
	u_int8_t nbuf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
	u_int8_t *pbuf;
	int len;
	static u_int32_t lasttm;
	while (1) {
		if (got_signal || (myticket >= lasttm + 3600)) {	// log ping/pong every hour

			err_msg("============= version: %s, myticket=%lu, master_slave=%d, current_remote=%s, loopback_check=%d",
				VERSION, myticket, master_slave, current_remote == 0 ? "MASTER" : "SLAVE", loopback_check);
			print_addrinfo(MASTER);
			if (master_slave)
				print_addrinfo(SLAVE);
			err_msg("master ping_send/pong_recv: %lu/%lu, ping_recv/pong_send: %lu/%lu, udp_send_err: %lu",
				ping_send[MASTER], pong_recv[MASTER], ping_recv[MASTER], pong_send[MASTER], udp_send_err[MASTER]);
			if (master_slave)
				err_msg(" slave ping_send/pong_recv: %lu/%lu, ping_recv/pong_send: %lu/%lu, udp_send_err: %lu", ping_send[SLAVE],
					pong_recv[SLAVE], ping_recv[SLAVE], pong_send[SLAVE], udp_send_err[SLAVE]);
			if (myticket >= lasttm + 3600) {
				ping_send[MASTER] = ping_send[SLAVE] = ping_recv[MASTER] = ping_recv[SLAVE] = 0;
				pong_send[MASTER] = pong_send[SLAVE] = pong_recv[MASTER] = pong_recv[SLAVE] = 0;
				lasttm = myticket;
			}
			err_msg("       raw interface recv:%lu/%lu send:%lu/%lu, raw_send_err: %lu", raw_recv_pkt, raw_recv_byte, raw_send_pkt, raw_send_byte,
				raw_send_err);
			err_msg("master udp interface recv:%lu/%lu send:%lu/%lu", udp_recv_pkt[MASTER], udp_recv_byte[MASTER], udp_send_pkt[MASTER],
				udp_send_byte[MASTER]);
			if (master_slave)
				err_msg(" slave udp interface recv:%lu/%lu send:%lu/%lu", udp_recv_pkt[SLAVE], udp_recv_byte[SLAVE], udp_send_pkt[SLAVE],
					udp_send_byte[SLAVE]);
			err_msg("udp %lu bytes, lz4 save %lu bytes, lz4 overhead %lu bytes, encrypt overhead %lu bytes, %.0f%%",
				udp_total, compress_save, compress_overhead, encrypt_overhead,
				100.0 * (udp_total - compress_save + compress_overhead + encrypt_overhead) / udp_total);
			got_signal = 0;
		}
		myticket++;
		if (run_seconds > 0) {
			if (myticket > run_seconds) {
				err_msg("run_seconds %d expired, exit", run_seconds);
				exit(0);
			}
		}
		if (mypassword[0]) {
			len = snprintf((char *)buf, MAX_PACKET_SIZE, "PASSWORD:%s", mypassword);
			if (debug)
				Debug("send password: %s", buf);
			len++;
			if ((enc_key_len > 0) || (lz4 > 0)) {
				len = do_encrypt((u_int8_t *) buf, len, nbuf);
				pbuf = nbuf;
			} else
				pbuf = buf;
			if (nat[MASTER] == 0)
				send_udp_to_remote(pbuf, len, MASTER);	// send to master
			if (master_slave && (nat[SLAVE] == 0))
				send_udp_to_remote(pbuf, len, SLAVE);	// send to slave
		}
		memcpy(buf, "PING:PING:", 10);
		len = 10;
		if ((enc_key_len > 0) || (lz4 > 0)) {
			len = do_encrypt((u_int8_t *) buf, len, nbuf);
			pbuf = nbuf;
		} else
			pbuf = buf;
		send_udp_to_remote(pbuf, len, MASTER);	// send to master
		ping_send[MASTER]++;

		if (master_status == STATUS_OK) {	// now master is OK
			if (myticket > last_pong[MASTER] + 5) {	// master OK->BAD
				master_status = STATUS_BAD;
				if (master_slave)
					current_remote = SLAVE;	// switch to SLAVE
				err_msg("master OK-->BAD, slave %s, current_remote is %s", slave_status == STATUS_OK ? "OK" : "BAD",
					current_remote == 0 ? "MASTER" : "SLAVE");
			}
		} else {	// now master is BAD
			if (myticket < last_pong[MASTER] + 4) {	// master BAD->OK
				master_status = STATUS_OK;
				current_remote = MASTER;	// switch to MASTER
				err_msg("master BAD-->OK, slave %s, current_remote is %s", slave_status == STATUS_OK ? "OK" : "BAD",
					current_remote == 0 ? "MASTER" : "SLAVE");
			}
		}

		if (master_slave) {
			send_udp_to_remote(pbuf, len, SLAVE);	// send to slave
			ping_send[SLAVE]++;

			if (slave_status == STATUS_OK) {	// now slave is OK
				if (myticket > last_pong[SLAVE] + 5) {	// slave OK->BAD
					slave_status = STATUS_BAD;
					err_msg("slave OK-->BAD, master %s, current_remote is %s", master_status == STATUS_OK ? "OK" : "BAD",
						current_remote == 0 ? "MASTER" : "SLAVE");
				}
			} else {	// now slave is BAD
				if (myticket < last_pong[SLAVE] + 4) {	// slave BAD->OK
					slave_status = STATUS_OK;
					err_msg("slave BAD-->OK, master %s, current_remote is %s", master_status == STATUS_OK ? "OK" : "BAD",
						current_remote == 0 ? "MASTER" : "SLAVE");
				}
			}
		}
		sleep(1);
	}
}

void process_raw_to_udp(void)	// used by mode==0 & mode==1
{
	u_int8_t *buf, mybuf[MAX_PACKET_SIZE + VLAN_TAG_LEN];
	u_int8_t nbuf[MAX_PACKET_SIZE + VLAN_TAG_LEN + EVP_MAX_BLOCK_LENGTH + LZ4_SPACE];
	u_int8_t *pbuf;
	int len;
	int offset = 0;

	while (1) {		// read from eth rawsocket
		if (mode == MODEE) {
			buf = mybuf;
#ifdef HAVE_PACKET_AUXDATA
			struct sockaddr from;
			struct iovec iov;
			struct msghdr msg;
			struct cmsghdr *cmsg;
			union {
				struct cmsghdr cmsg;
				char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
			} cmsg_buf;
			msg.msg_name = &from;
			msg.msg_namelen = sizeof(from);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = &cmsg_buf;
			msg.msg_controllen = sizeof(cmsg_buf);
			msg.msg_flags = 0;

			offset = VLAN_TAG_LEN;
			iov.iov_len = MAX_PACKET_SIZE;
			iov.iov_base = buf + offset;
			len = recvmsg(fdraw, &msg, MSG_TRUNC);
			if (len <= 0)
				continue;
			if (len >= MAX_PACKET_SIZE) {
				err_msg("recv long pkt from raw, len=%d", len);
				len = MAX_PACKET_SIZE;
			}
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
				struct tpacket_auxdata *aux;
				struct vlan_tag *tag;

				if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))
				    || cmsg->cmsg_level != SOL_PACKET || cmsg->cmsg_type != PACKET_AUXDATA)
					continue;

				aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

#if defined(TP_STATUS_VLAN_VALID)
				if ((aux->tp_vlan_tci == 0)
				    && !(aux->tp_status & TP_STATUS_VLAN_VALID))
#else
				if (aux->tp_vlan_tci == 0)	/* this is ambigious but without the */
#endif
					continue;

				if (debug)
					Debug("len=%d, iov_len=%d, ", len, (int)iov.iov_len);

				len = len > iov.iov_len ? iov.iov_len : len;
				if (len < 12)	// MAC_len * 2
					break;
				if (debug)
					Debug("len=%d", len);

				memmove(buf, buf + VLAN_TAG_LEN, 12);
				offset = 0;

				/*
				 * Now insert the tag.
				 */
				tag = (struct vlan_tag *)(buf + 12);
				if (debug)
					Debug("insert vlan id, recv len=%d", len);

#ifdef TP_STATUS_VLAN_TPID_VALID
				tag->vlan_tpid = ((aux->tp_vlan_tpid || (aux->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? htons(aux->tp_vlan_tpid) : ETHP8021Q);
#else
				tag->vlan_tpid = ETHP8021Q;
#endif
				tag->vlan_tci = htons(aux->tp_vlan_tci);

				/* Add the tag to the packet lengths.
				 */
				len += VLAN_TAG_LEN;
				break;
			}
#else
			len = recv(fdraw, buf, MAX_PACKET_SIZE, 0);
#endif
		} else if ((mode == MODEI) || (mode == MODEB)) {
			buf = mybuf;
			len = read(fdraw, buf, MAX_PACKET_SIZE);
			if (len >= MAX_PACKET_SIZE) {
				err_msg("recv long pkt from raw, len=%d", len);
				len = MAX_PACKET_SIZE;
			}
		} else if (mode == MODET) {
			struct pcap_pkthdr *header;
			int r = pcap_next_ex(pcap_handle, &header, (const u_char **)&buf);
			if (r <= 0)
				continue;
			len = header->len;
		} else
			return;

		if (len <= 0)
			continue;
		if (write_only)
			continue;	// write only

		raw_recv_pkt++;
		raw_recv_byte += len;
		if (loopback_check && do_loopback_check(buf + offset, len))
			continue;
		if (debug) {
			printPacket((EtherPacket *) (buf + offset), len, "from local  rawsocket:");
			if (offset)
				Debug("offset=%d", offset);
		}
		if (!read_only && fixmss)	// read only, no fix_mss
			fix_mss(buf + offset, len, current_remote);

		if (vlan_map && len >= 16) {
			struct vlan_tag *tag;
			tag = (struct vlan_tag *)(buf + offset + 12);
			if (tag->vlan_tpid == ETHP8021Q) {
				int vlan;
				vlan = ntohs(tag->vlan_tci) & 0xfff;
				if (my_vlan[vlan] != vlan) {
					tag->vlan_tci = htons((ntohs(tag->vlan_tci) & 0xf000) + my_vlan[vlan]);
					if (debug) {
						if (debug)
							Debug("maping vlan %d to %d", vlan, my_vlan[vlan]);
						printPacket((EtherPacket *) (buf + offset), len, "from local  rawsocket:");
					}
				}
			}
		}
		if ((enc_key_len > 0) || (lz4 > 0)) {
			len = do_encrypt((u_int8_t *) buf + offset, len, nbuf);
			pbuf = nbuf;
		} else
			pbuf = buf + offset;

		send_udp_to_remote(pbuf, len, current_remote);
	}
}

void save_remote_addr(struct sockaddr_storage *rmt, int sock_len, int index)
{
	char rip[200];
	if (memcmp((void *)rmt, (void *)(&remote_addr[index]), sock_len) == 0)
		return;
	if (rmt->ss_family == AF_INET) {
		struct sockaddr_in *r = (struct sockaddr_in *)rmt;
		struct sockaddr_in *cmdr = (struct sockaddr_in *)&cmd_remote_addr[index];
		if (((cmdr->sin_addr.s_addr == 0) || (cmdr->sin_addr.s_addr == r->sin_addr.s_addr))
		    && ((cmdr->sin_port == 0) || (cmdr->sin_port == r->sin_port))) {
			memcpy((void *)&remote_addr[index], rmt, sock_len);
			err_msg("nat mode, change %s remote to %s:%d", index == 0 ? "master" : "slave",
				inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), ntohs(r->sin_port));
		} else
			err_msg("nat mode, do not change %s remote to %s:%d", index == 0 ? "master" : "slave",
				inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), ntohs(r->sin_port));
	} else if (rmt->ss_family == AF_INET6) {
		struct sockaddr_in6 *r = (struct sockaddr_in6 *)rmt;
		struct sockaddr_in6 *cmdr = (struct sockaddr_in6 *)&cmd_remote_addr[index];
		struct in6_addr ia6 = IN6ADDR_ANY_INIT;
		if (((memcmp(&ia6, &cmdr->sin6_addr, 16) == 0) || (memcmp(&r->sin6_addr, &cmdr->sin6_addr, 16) == 0))
		    && ((cmdr->sin6_port == 0) || (cmdr->sin6_port == r->sin6_port))) {
			memcpy((void *)&remote_addr[index], rmt, sock_len);
			err_msg("nat mode, change %s remote to [%s]:%d", index == 0 ? "master" : "slave",
				inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), ntohs(r->sin6_port));
		}
		err_msg("nat mode, do not change %s remote to [%s]:%d", index == 0 ? "master" : "slave",
			inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), ntohs(r->sin6_port));
	}
}

void add_to_udp_frag_buf(time_t rcvt, int seq, unsigned char *buf, int len)
{
	if (packet_bufs[seq].rcvt > 0)	// del old packet
		free(packet_bufs[seq].buf);
	packet_bufs[seq].buf = malloc(len);
	if (packet_bufs[seq].buf == NULL) {
		Debug("malloc error\n");
		packet_bufs[seq].rcvt = 0;
		return;
	}
	memcpy(packet_bufs[seq].buf, buf, len);
	packet_bufs[seq].len = len;
	packet_bufs[seq].rcvt = rcvt;
	if (debug)
		Debug("udp_frag seq %d, len=%d stored", seq, len);
}

int do_udp_frag_recv(unsigned char *buf, int len)
{
	time_t tm = time(NULL);
	int seq = (buf[6] << 8) + buf[7];
	int pair_seq = (seq & 0xfffe) + ((seq & 1) ^ 1);
	if (debug)
		Debug("Got udp_frag seq %d, len=%d", seq, len - 8);
	if ((len > 1008) || (len < 8)) {
		if (debug)
			Debug("len=%d is invalid, drop it\n", len);
		return 0;
	}
	if (packet_bufs[pair_seq].rcvt == 0) {	// pair not in buf, store in buf
		add_to_udp_frag_buf(tm, seq, buf + 8, len - 8);
		return 0;
	}

	if (tm - packet_bufs[pair_seq].rcvt > 1) {	// pair time is too long(>1s), invalid, store in buf
		add_to_udp_frag_buf(tm, seq, buf + 8, len - 8);
		return 0;
	}

	if ((seq & 1) == 0) {	// this is the first packet
		memmove(buf, buf + 8, len - 8);
		memcpy(buf + len - 8, packet_bufs[pair_seq].buf, packet_bufs[pair_seq].len);
	} else {
		memmove(buf + packet_bufs[pair_seq].len, buf + 8, len - 8);
		memcpy(buf, packet_bufs[pair_seq].buf, packet_bufs[pair_seq].len);
	}
	len = len - 8 + packet_bufs[pair_seq].len;
	packet_bufs[pair_seq].rcvt = 0;
	packet_bufs[pair_seq].len = 0;
	free(packet_bufs[pair_seq].buf);
	packet_bufs[pair_seq].buf = NULL;
	if (debug)
		Debug("udp_frag new pkt len %d", len);
	return len;
}

void process_udp_to_raw(int index)
{
	u_int8_t buf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH + LZ4_SPACE];
	u_int8_t nbuf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
	u_int8_t *pbuf;
	int len;

	while (1) {		// read from remote udp
		if (nat[index]) {
			struct sockaddr_storage rmt;
			socklen_t sock_len = sizeof(struct sockaddr_storage);
			len = recvfrom(fdudp[index], buf, MAX_PACKET_SIZE, 0, (struct sockaddr *)&rmt, &sock_len);
			if (debug) {
				char rip[200];
				if (rmt.ss_family == AF_INET) {
					struct sockaddr_in *r = (struct sockaddr_in *)&rmt;
					if (debug)
						Debug("nat mode: len %d recv from %s:%d",
						      len, inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), ntohs(r->sin_port));
				} else if (rmt.ss_family == AF_INET6) {
					struct sockaddr_in6 *r = (struct sockaddr_in6 *)&rmt;
					if (debug)
						Debug("nat mode: len %d recv from [%s]:%d",
						      len, inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), ntohs(r->sin6_port));
				}
			}
			if (len <= 0)
				continue;

			if (len >= MAX_PACKET_SIZE) {
				err_msg("recv long pkt from udp, len=%d", len);
				len = MAX_PACKET_SIZE;
			}

			if ((mtu > 0) && (memcmp(buf, "UDPFRG", 6) == 0)) {
				len = do_udp_frag_recv(buf, len);
				if (len <= 0)	//  waiting the pair packet
					continue;
			}

			if ((enc_key_len > 0) || (lz4 > 0)) {
				len = do_decrypt((u_int8_t *) buf, len, nbuf);
				pbuf = nbuf;
			} else
				pbuf = buf;

			if (len <= 0)
				continue;

			udp_recv_pkt[index]++;
			udp_recv_byte[index] += len;
			nbuf[len] = 0;
			if (mypassword[0] == 0) {	// no password set, accept new ip and port
				if (debug)
					Debug("no password, accept new remote ip and port");
				save_remote_addr(&rmt, sock_len, index);
				if (memcmp(pbuf, "PASSWORD:", 9) == 0)	// got password packet, skip this packet
					continue;
			} else {
				if (memcmp(pbuf, "PASSWORD:", 9) == 0) {	// got password packet
					if (debug)
						Debug("password packet from remote %s", pbuf);
					if ((memcmp(pbuf + 9, mypassword, strlen(mypassword)) == 0)
					    && (*(pbuf + 9 + strlen(mypassword))
						== 0)) {
						if (debug)
							Debug("password ok");
						save_remote_addr(&rmt, sock_len, index);
					} else if (debug)
						Debug("passowrd error");
					continue;
				}
				if (memcmp((void *)&remote_addr[index], &rmt, sock_len)) {
					if (debug)
						Debug("packet from unknow host, drop...");
					continue;
				}
			}
		} else {
			len = recv(fdudp[index], buf, MAX_PACKET_SIZE, 0);
			if (len >= MAX_PACKET_SIZE) {
				err_msg("recv long pkt from UDP, len=%d", len);
				len = MAX_PACKET_SIZE;
			}
			if (len <= 0)
				continue;

			if ((mtu > 0) && (memcmp(buf, "UDPFRG", 6) == 0)) {
				len = do_udp_frag_recv(buf, len);
				if (len <= 0)	//  waiting the pair packet
					continue;
			}

			if ((enc_key_len > 0) || (lz4 > 0)) {
				len = do_decrypt((u_int8_t *) buf, len, nbuf);
				pbuf = nbuf;
			} else
				pbuf = buf;
			if (len <= 0)
				continue;
			udp_recv_pkt[index]++;
			udp_recv_byte[index] += len;
			if (memcmp(pbuf, "PASSWORD:", 9) == 0) {	// got password packet
				if (debug) {
					Debug("password packet from remote %s", pbuf);
					if ((memcmp(pbuf + 9, mypassword, strlen(mypassword)) == 0)
					    && (*(pbuf + 9 + strlen(mypassword)) == 0))
						Debug("password ok");
					else
						Debug("error\n");
				}
				continue;
			}
		}

		if (memcmp(pbuf, "PING:PING:", 10) == 0) {
#ifdef DEBUGPINGPONG
			Debug("ping from index %d udp", index);
#endif
			ping_recv[index]++;
			memcpy(buf, "PONG:PONG:", 10);
			len = 10;
			if ((enc_key_len > 0) || (lz4 > 0)) {
				len = do_encrypt((u_int8_t *) buf, len, nbuf);
				pbuf = nbuf;
			} else
				pbuf = buf;
			send_udp_to_remote(pbuf, len, index);
			pong_send[index]++;
			continue;
		}

		if (memcmp(pbuf, "PONG:PONG:", 10) == 0) {
#ifdef DEBUGPINGPONG
			Debug("pong from index %d udp", index);
#endif
			last_pong[index] = myticket;
			pong_recv[index]++;
			continue;
		}

		if (read_only)
			continue;	// read only
		if (!write_only && fixmss)	// write only, no fix_mss
			fix_mss(pbuf, len, index);

		if (debug)
			printPacket((EtherPacket *) pbuf, len, "from remote udpsocket:");
		raw_send_pkt++;
		raw_send_byte += len;

		if (vlan_map && len >= 16) {
			struct vlan_tag *tag;
			tag = (struct vlan_tag *)(pbuf + 12);
			if (tag->vlan_tpid == ETHP8021Q) {
				int vlan = ntohs(tag->vlan_tci) & 0xfff;
				if (remote_vlan[vlan] != vlan) {
					tag->vlan_tci = htons((ntohs(tag->vlan_tci) & 0xf000) + remote_vlan[vlan]);
					if (debug) {
						Debug("maping vlan %d back to %d", vlan, remote_vlan[vlan]);
						printPacket((EtherPacket *) (pbuf), len, "from remote udpsocket:");
					}
				}
			}
		}

		if (mode == MODEE) {
			struct sockaddr_ll sll;
			memset(&sll, 0, sizeof(sll));
			sll.sll_family = AF_PACKET;
			sll.sll_protocol = htons(ETH_P_ALL);
			sll.sll_ifindex = ifindex;
			if (sendto(fdraw, pbuf, len, 0, (struct sockaddr *)&sll, sizeof(sll)) != len)
				raw_send_err++;
		} else if ((mode == MODEI) || (mode == MODEB))
			if (write(fdraw, pbuf, len) != len)
				raw_send_err++;
	}
}

void process_udp_to_raw_master(void)
{
	process_udp_to_raw(MASTER);
}

void process_udp_to_raw_slave(void)
{
	process_udp_to_raw(SLAVE);
}

int open_tun(const char *dev, char **actual)
{
	struct ifreq ifr;
	int fd;
	// char *device = "/dev/tun"; //uClinux tun
	char *device = "/dev/net/tun";	//RedHat tun
	int size;

	if ((fd = open(device, O_RDWR)) < 0)	//???? 
	{
		Debug("Cannot open TUN/TAP dev %s", device);
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_NO_PI;
	if (!strncmp(dev, "tun", 3)) {
		ifr.ifr_flags |= IFF_TUN;
	} else if (!strncmp(dev, "tap", 3)) {
		ifr.ifr_flags |= IFF_TAP;
	} else {
		Debug("I don't recognize device %s as a TUN or TAP device", dev);
		exit(1);
	}
	if (strlen(dev) > 3)	//unit number specified? 
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)	//? 
	{
		Debug("Cannot ioctl TUNSETIFF %s", dev);
		exit(1);
	}
	Debug("TUN/TAP device %s opened", ifr.ifr_name);
	size = strlen(ifr.ifr_name) + 1;
	*actual = (char *)malloc(size);
	memcpy(*actual, ifr.ifr_name, size);
	// the following maybe no use
	int n = 10 * 1024 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
	if (debug) {
		socklen_t ln = sizeof(n);
		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0)
			Debug("RAW socket RCVBUF setting to %d", n);
	}
	return fd;
}

void read_vlan_map_file(char *fname)
{
	int vlan;
	FILE *fp;
	char buf[MAXLEN];
	for (vlan = 0; vlan < 4096; vlan++)
		my_vlan[vlan] = remote_vlan[vlan] = vlan;
	fp = fopen(fname, "r");
	if (fp == NULL)
		return;
	while (fgets(buf, MAXLEN, fp)) {
		int myvlan, remotevlan;
		char *p;
		p = buf;
		while (isblank(*p))
			p++;
		if (!isdigit(*p))
			continue;
		myvlan = atoi(p) & 0xfff;
		while (isdigit(*p))
			p++;
		while (isblank(*p))
			p++;
		if (!isdigit(*p))
			continue;
		remotevlan = atoi(p) & 0xfff;
		my_vlan[myvlan] = remotevlan;
		remote_vlan[remotevlan] = myvlan;
	}
	fclose(fp);
}

void usage(void)
{
	printf("EthUDP Version: %s, by james@ustc.edu.cn (https://github.com/bg6cq/ethudp)\n", VERSION);
	printf("Usage:\n");
	printf("./EthUDP -e [ options ] localip localport remoteip remoteport eth? \\\n");
	printf("            [ localip localport remoteip remoteport ]\n");
	printf("./EthUDP -i [ options ] localip localport remoteip remoteport ipaddress masklen \\\n");
	printf("            [ localip localport remoteip remoteport ]\n");
	printf("./EthUDP -b [ options ] localip localport remoteip remoteport bridge \\\n");
	printf("            [ localip localport remoteip remoteport ]\n");
	printf("./EthUDP -t localip localport remoteip remoteport eth? [ pcap_filter_string ]\n");
	printf(" options:\n");
	printf("    -p password\n");
	printf("    -enc [ xor|aes-128|aes-192|aes-256 ]\n");
	printf("    -k key_string\n");
	printf("    -lz4 [ 0-9 ]     lz4 acceleration, default is 0(disable), 1 is best, 9 is fast\n");
	printf("    -mss mss         change tcp SYN mss\n");
	printf("    -mtu mtu         fragment udp to mtu - 28 bytes packets, 1036 - 1500\n");
	printf("    -map vlanmap.txt vlan maping\n");
	printf("    -dev dev_name    rename tap interface to dev_name(mode i & b)\n");
	printf("    -n name          name for syslog prefix\n");
	printf("    -c run_cmd       run run_cmd after tunnel connected\n");
	printf("    -x run_seconds   child process exit after run_seconds run\n");
	printf("    -d    enable debug\n");
	printf("    -r    read only of ethernet interface\n");
	printf("    -w    write only of ethernet interface\n");
	printf("    -B    benchmark\n");
	printf("    -l    packet_len\n");
	printf("    -nopromisc    do not set ethernet interface to promisc mode(mode e)\n");
	printf("    -noloopcheck  do not check loopback(-r default do check)\n");
	printf("    -loopcheck    do check loopback\n");
	printf(" HUP  signal: print statistics\n");
	printf(" USR1 signal: reset statistics\n");
	exit(0);
}

#define BENCHCNT 300000

void do_benchmark(void)
{
#ifdef ENABLE_OPENSSL
	u_int8_t buf[MAX_PACKET_SIZE];
	u_int8_t nbuf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
	unsigned long int pkt_cnt;
	unsigned long int pkt_len = 0, pkt_len_send = 0;
	int len;
	struct timeval start_tm, end_tm;
	gettimeofday(&start_tm, NULL);
	fprintf(stderr, "benchmarking for %d packets, %d size...\n", BENCHCNT, packet_len);
	fprintf(stderr, "enc_algorithm = %s\n",
		enc_algorithm == XOR ? "xor" : enc_algorithm == AES_128 ? "aes-128" : enc_algorithm == AES_192 ? "aes-192" : enc_algorithm ==
		AES_256 ? "aes-256" : "none");
	fprintf(stderr, "      enc_key = %s\n", enc_key);
	fprintf(stderr, "      key_len = %d\n", enc_key_len);
	fprintf(stderr, "          lz4 = %d\n", lz4);
	pkt_cnt = BENCHCNT;
	memset(buf, 'a', packet_len);

	while (1) {
		len = packet_len;
		pkt_len += len;
		len = do_encrypt(buf, len, nbuf);
		pkt_len_send += len;
		pkt_cnt--;
		if (pkt_cnt == 0)
			break;
	}
	gettimeofday(&end_tm, NULL);
	float tspan = ((end_tm.tv_sec - start_tm.tv_sec) * 1000000L + end_tm.tv_usec) - start_tm.tv_usec;
	tspan = tspan / 1000000L;
	fprintf(stderr, "%0.3f seconds\n", tspan);
	fprintf(stderr, "PPS: %.0f PKT/S, %lu(%lu) Byte, %.0f(%.0f) Byte/S\n", (float)BENCHCNT / tspan, pkt_len, pkt_len_send, 1.0 * pkt_len / tspan,
		1.0 * pkt_len_send / tspan);
	fprintf(stderr, "UDP BPS: %.0f(%.0f) BPS\n", 8.0 * pkt_len / tspan, 8.0 * pkt_len_send / tspan);
#endif
	exit(0);
}

int main(int argc, char *argv[])
{
	pthread_t tid;
	int i = 1;
	int got_one = 0;
	ETHP8021Q = htons(0x8100);
	do {
		got_one = 1;
		if (argc - i <= 0)
			usage();
		if (strcmp(argv[i], "-e") == 0)
			mode = MODEE;
		else if (strcmp(argv[i], "-i") == 0)
			mode = MODEI;
		else if (strcmp(argv[i], "-b") == 0)
			mode = MODEB;
		else if (strcmp(argv[i], "-t") == 0)
			mode = MODET;
		else if (strcmp(argv[i], "-d") == 0)
			debug = 1;
		else if (strcmp(argv[i], "-r") == 0) {
			read_only = 1;
			loopback_check = 1;
		} else if (strcmp(argv[i], "-w") == 0)
			write_only = 1;
		else if (strcmp(argv[i], "-nopromisc") == 0)
			nopromisc = 1;
		else if (strcmp(argv[i], "-noloopcheck") == 0)
			loopback_check = 0;
		else if (strcmp(argv[i], "-loopcheck") == 0)
			loopback_check = 1;
		else if (strcmp(argv[i], "-B") == 0)
			do_benchmark();
		else if (strcmp(argv[i], "-mss") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			fixmss = atoi(argv[i]);
		} else if (strcmp(argv[i], "-mtu") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			mtu = atoi(argv[i]);
			if ((mtu < 1036) || (mtu > 1500)) {
				printf("invalid mtu %d\n", mtu);
				usage();
			}
		} else if (strcmp(argv[i], "-map") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			vlan_map = 1;
			read_vlan_map_file(argv[i]);
		} else if (strcmp(argv[i], "-dev") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			strncpy(dev_name, argv[i], MAXLEN - 1);
		} else if (strcmp(argv[i], "-n") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			strncpy(name, argv[i], MAXLEN - 1);
		} else if (strcmp(argv[i], "-lz4") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			lz4 = atoi(argv[i]);
		} else if (strcmp(argv[i], "-l") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			packet_len = atoi(argv[i]);
		} else if (strcmp(argv[i], "-p") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			strncpy(mypassword, argv[i], MAXLEN - 1);
		} else if (strcmp(argv[i], "-enc") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			if (strcmp(argv[i], "xor") == 0)
				enc_algorithm = XOR;
#ifdef ENABLE_OPENSSL
			else if (strcmp(argv[i], "aes-128") == 0)
				enc_algorithm = AES_128;
			else if (strcmp(argv[i], "aes-192") == 0)
				enc_algorithm = AES_192;
			else if (strcmp(argv[i], "aes-256") == 0)
				enc_algorithm = AES_256;
#endif
		} else if (strcmp(argv[i], "-k") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			memset(enc_key, 0, MAXLEN);
			strncpy((char *)enc_key, argv[i], MAXLEN - 1);
			enc_key_len = strlen((char *)enc_key);
		} else if (strcmp(argv[i], "-x") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			run_seconds = atoi(argv[i]);
		} else if (strcmp(argv[i], "-c") == 0) {
			i++;
			if (argc - i <= 0)
				usage();
			memset(run_cmd, 0, MAXLEN);
			strncpy((char *)run_cmd, argv[i], MAXLEN - 1);
		} else
			got_one = 0;
		if (got_one)
			i++;
	}
	while (got_one);
	if ((mode == MODEE) || (mode == MODEB)) {
		if (argc - i == 9)
			master_slave = 1;
		else if (argc - i != 5)
			usage();
	}
	if (mode == MODEI) {
		if (argc - i == 10)
			master_slave = 1;
		else if (argc - i != 6)
			usage();
	}
	if (mode == MODET) {
		if (argc - i < 5)
			usage();
	}
	// enc_algorithm set, but enc_key not set, set enc_key to 123456
	if ((enc_algorithm != 0) && (enc_key_len == 0)) {
		memset(enc_key, 0, MAXLEN);
		strncpy((char *)enc_key, "123456", MAXLEN - 1);
		enc_key_len = strlen((char *)enc_key);
	} else if ((enc_algorithm == 0) && (enc_key_len != 0))	// enc_key set, but enc_algorithm not set, set enc_algorithm to AES-128
		enc_algorithm = AES_128;
	if (mode == -1)
		usage();
	if (debug) {
		printf("         debug = 1\n");
		printf("          mode = %d (0 raw eth bridge, 1 interface, 2 bridge, 3 tcpdump)\n", mode);
		printf("      password = %s\n", mypassword);
		printf(" enc_algorithm = %s\n", enc_algorithm == XOR ? "xor"
#ifdef ENABLE_OPENSSL
		       : enc_algorithm == AES_128 ? "aes-128" : enc_algorithm == AES_192 ? "aes-192" : enc_algorithm == AES_256 ? "aes-256"
#endif
		       : "none");
		printf("       enc_key = %s\n", enc_key);
		printf("       key_len = %d\n", enc_key_len);
		printf("  master_slave = %d\n", master_slave);
		printf("           mss = %d\n", fixmss);
		printf("           mtu = %d\n", mtu);
		printf("     read_only = %d\n", read_only);
		printf("loopback_check = %d\n", loopback_check);
		printf("    write_only = %d\n", write_only);
		printf("     nopromisc = %d\n", nopromisc);
		printf("           lz4 = %d\n", lz4);
		printf("      dev_name = %s\n", dev_name);
		printf("       run_cmd = %s\n", run_cmd);
		printf("   run_seconds = %d\n", run_seconds);
		printf("      cmd_line = ");
		int n;
		for (n = i; n < argc; n++)
			printf("%s ", argv[n]);
		printf("\n");
		if (vlan_map) {
			int vlan;
			printf("vlan mapping\n");
			for (vlan = 0; vlan < 4095; vlan++)
				if (my_vlan[vlan] != vlan)
					printf(" % 4d --> % 4d\n", vlan, my_vlan[vlan]);
		}
		printf("\n");
	}

	if (debug == 0) {
		daemon_init("EthUDP", LOG_DAEMON);
		while (1) {
			int pid;
			pid = fork();
			if (pid == 0)	// child do the job
				break;
			else if (pid == -1)	// error
				exit(0);
			else
				wait(NULL);	// parent wait for child
			sleep(2);	// wait 2 second, and rerun
		}
	}

	signal(SIGHUP, sig_handler_hup);
	signal(SIGUSR1, sig_handler_usr1);

	if (mode == MODEE) {	// eth bridge mode
		fdudp[MASTER] = udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
		if (master_slave)
			fdudp[SLAVE] = udp_xconnect(argv[i + 5], argv[i + 6], argv[i + 7], argv[i + 8], SLAVE);
		fdraw = open_rawsocket(argv[i + 4], &ifindex);
	} else if (mode == MODEI) {	// interface mode
		char *actualname = NULL;
		char buf[MAXLEN];
		fdudp[MASTER] = udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
		if (master_slave)
			fdudp[SLAVE] = udp_xconnect(argv[i + 6], argv[i + 7], argv[i + 8], argv[i + 9], SLAVE);
		fdraw = open_tun("tap", &actualname);
		if (dev_name[0])
			snprintf(buf, MAXLEN, "%s link set %s name %s; %s addr add %s/%s dev %s; %s link set %s up",
				 IPCMD, actualname, dev_name, IPCMD, argv[i + 4], argv[i + 5], dev_name, IPCMD, dev_name);
		else
			snprintf(buf, MAXLEN, "%s addr add %s/%s dev %s; %s link set %s up", IPCMD, argv[i + 4], argv[i + 5], actualname, IPCMD, actualname);
		if (debug)
			printf(" run cmd: %s\n", buf);
		if (system(buf) != 0)
			printf(" run cmd: %s returned not 0\n", buf);
		if (debug) {
			snprintf(buf, MAXLEN, "%s addr", IPCMD);
			if (system(buf) != 0)
				printf(" run cmd: %s returned not 0\n", buf);
		}
	} else if (mode == MODEB) {	// bridge mode
		char *actualname = NULL;
		char buf[MAXLEN];
		fdudp[MASTER] = udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
		if (master_slave)
			fdudp[SLAVE] = udp_xconnect(argv[i + 5], argv[i + 6], argv[i + 7], argv[i + 8], SLAVE);
		fdraw = open_tun("tap", &actualname);
		if (dev_name[0])
			snprintf(buf, MAXLEN, "%s link set %s name %s; %s link set %s up; %s addif %s %s",
				 IPCMD, actualname, dev_name, IPCMD, dev_name, BRIDGECMD, argv[i + 4], dev_name);
		else
			snprintf(buf, MAXLEN, "%s link set %s up; %s addif %s %s", IPCMD, actualname, BRIDGECMD, argv[i + 4], actualname);
		if (debug)
			printf(" run cmd: %s\n", buf);
		if (system(buf) != 0)
			printf(" run cmd: %s returned not 0\n", buf);
		if (debug) {
			snprintf(buf, MAXLEN, "%s addr", IPCMD);
			if (system(buf) != 0)
				printf(" run cmd: %s returned not 0\n", buf);
			snprintf(buf, MAXLEN, "%s show", BRIDGECMD);
			if (system(buf) != 0)
				printf(" run cmd: %s returned not 0\n", buf);
		}
	} else if (mode == MODET) {	// tcpdump mode
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		read_only = 1;
		fdudp[MASTER] = udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
		pcap_handle = pcap_open_live(argv[i + 4], MAX_PACKET_SIZE, 0, 1000, errbuf);
		if (argc - i == 6) {
			struct bpf_program pgm;
			if (pcap_compile(pcap_handle, &pgm, argv[i + 5], 1, PCAP_NETMASK_UNKNOWN) == -1) {
				err_msg("pcap_filter compile error\n");
				exit(0);
			}
			if (pcap_setfilter(pcap_handle, &pgm) == -1) {
				err_msg("pcap_setfilter error\n");
				exit(0);
			}
		}
	}
	if (run_cmd[0]) {	// run command when tunnel connected
		if (debug)
			printf(" run user cmd: %s\n", run_cmd);
		if (system(run_cmd) != 0)
			printf(" run cmd: %s returned not 0\n", run_cmd);
	}
	// create a pthread to forward packets from master udp to raw
	if (pthread_create(&tid, NULL, (void *)process_udp_to_raw_master, NULL) != 0)
		err_sys("pthread_create udp_to_raw_master error");

	// create a pthread to forward packets from slave udp to raw
	if (master_slave)
		if (pthread_create(&tid, NULL, (void *)process_udp_to_raw_slave, NULL) != 0)
			err_sys("pthread_create udp_to_raw_slave error");

	if (pthread_create(&tid, NULL, (void *)send_keepalive_to_udp, NULL) != 0)	// send keepalive to remote  
		err_sys("pthread_create send_keepalive error");

	//  forward packets from raw to udp
	process_raw_to_udp();

	return 0;
}
