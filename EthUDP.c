#include <linux/if_packet.h>
#include <linux/if_ether.h> 
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <fcntl.h>


// 0       6      12      12/16 14/18           18/22
// +-------+-------+---------+----+---------------+
// | DMAC  | SMAC  |8100 VLAN|Type|Payload (4Bfix)|
// +-------+-------+---------+----+---------------+
//                  <-------> when VLAN == Yes

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

#define DEBUG		0


#define MAX_PACKET_SIZE	2048


#define IFNAME	"eth1"


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


/**
 * Print IPEC packet content
 */
void printPacket(EtherPacket *packet, ssize_t packetSize, char *message) {
  printf("%s #%d (VLAN %d) from %08x%04x to %08x%04x\n",
	 message, ntohl(packet->payload), ntohl(packet->VLANTag) & 0xFFF,
	 ntohs(packet->srcMAC1), ntohl(packet->srcMAC2),
	 ntohs(packet->destMAC1), ntohl(packet->destMAC2));
}


/**
 * Send packets to terminals
 */
void sendPackets(int32_t fd, int32_t ifindex, uint16_t SrcMAC1, uint32_t SrcMAC2,
		 uint16_t DestMAC1, uint32_t DestMAC2, uint16_t type, uint32_t vlanTag,
		 int32_t *count) {
  int32_t i;
  unsigned char packet[MAX_PACKET_SIZE];
  // unsigned char *payload = "Hello!";

  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);	// Ethernet type = Trans. Ether Bridging
  sll.sll_ifindex = ifindex;

  ssize_t packetSize;
/* = createPacket((EtherPacket*)packet, DestMAC1, DestMAC2,
				    SrcMAC1, SrcMAC2, type, vlanTag, (*count)++);
*/
  ssize_t sizeout = sendto(fd, packet, packetSize, 0,
			   (struct sockaddr *)&sll, sizeof(sll));
  printPacket((EtherPacket*)packet, packetSize, "Sent:    ");
  if (sizeout < 0) {
    perror("sendto");
  } else {
    if (DEBUG) {
      printf("%d bytes sent through interface (ifindex) %d\n",
	     (int32_t)sizeout, (int32_t)ifindex);
    }
  }
}

void recvPKT(int32_t fd, int32_t ifindex){
	unsigned char buf[MAX_PACKET_SIZE];
	int count=0;
    while(1) {
		ssize_t sizein = recv(fd, buf, MAX_PACKET_SIZE, 0);
   	 	if (sizein >= 0) {
			count++;
			if(count==100) {
				printf("got 100 pkts, exit\n");
				exit(0);
			}
   	   		EtherPacket *packet = (EtherPacket*) buf;
      		printPacket(packet, sizein, "Received:");
		} else {
			printf("recv got %d, exit\n",sizein);
			exit(0);
		}
	}
}


/**
 * Main program
 */
int32_t main(int32_t argc, char **argv) {
  int32_t ifindex;
  int32_t myTermNum = 0;
  int32_t destTermNum = 0;
  int32_t ifnum = 0;
  uint16_t vlanID = 1;
  int32_t i;

  int32_t fd = open_socket("eth1", &ifindex);

  // Set non-blocking mode:
  // int32_t flags = fcntl(fd, F_GETFL, 0);
  // fcntl(fd, F_SETFL, O_NONBLOCK | flags);

  recvPKT(fd,ifindex);
}
