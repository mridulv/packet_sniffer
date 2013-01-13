#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<linux/if_arp.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/icmp.h>
#include<sys/types.h>
#include<linux/ip.h>
#include<netinet/in.h>
#include<string.h>

#define PACKET_BUFFER_SIZE 65536
#define PACKET_LENGTH_INSTANCE 10

typedef struct
{
	int host;
	int broadcast;
	int multicast;
	int otherhost;
	int outgoing;
} PKT_TYPE;

typedef struct 
{
	int tcp;
	int udp;
	int icmp;	
} T_PROTO;

typedef struct
{
	char *device;
	int promiscous;
	PKT_TYPE packet_type;
	int packet_length[10][2];
	int network_protocol;
	T_PROTO transport_protocol;
	char *src_ip; 
	char *dest_ip;
} PKT_OPT;

typedef struct
{
	int arp;
	int tcp;
	int udp;
	int icmp;	
} PKT_PRT;

int CreateRawSocket(int protocol_to_sniff);
struct ifreq BindSocketToInterface(char *device, int rawsock, int protocol);
void ParseEthernetHeader(unsigned char* packet, int len);
void ParseTcpHeader(unsigned char *packet, int len);
void ParseIpheader(unsigned char *packet, int len);
void PrintInHex(char *msg, unsigned char *p, int len);
void sniffer_init(PKT_OPT *packet_options);
void flag_init(PKT_PRT *packet_print_flags);
