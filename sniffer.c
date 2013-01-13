#include "sniffer.h"

int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;
	if((rawsock=socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))==-1)
	{
		perror("Error Creating Raw Socket");
		exit(-1);
	}	
	return rawsock;
}

struct ifreq BindSocketToInterface(char *device, int rawsock, int protocol)
{
	struct sockaddr_ll sll;
	struct ifreq ifr;
	
	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));

	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr))==-1)
	{
		perror("Error getting Interface Index");
		exit(-1);
	}
	
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex=ifr.ifr_ifindex;
	sll.sll_protocol=htons(protocol);

	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))==-1)
	{
		perror("Error binding Raw Socket to Interface");
		exit(-1);
	}
	return ifr;
}

void ParseEthernetHeader(unsigned char* packet, int len)
{
	struct ethhdr *eth_head;
	if(len>sizeof(struct ethhdr))
	{
		eth_head=(struct ethhdr *)packet;
		
		PrintInHex("DEST MAC: ", eth_head->h_dest, 6);
		printf("\n");

		PrintInHex("SRC MAC: ", eth_head->h_source, 6);
		printf("\n");

		PrintInHex("PROTOCOL MAC: ", (void *)&eth_head->h_proto, 2);
		
		if(ntohs(eth_head->h_proto)==ETH_P_IP) printf("\nNetwork Layer Protocol: IP\n");
		if(ntohs(eth_head->h_proto)==ETH_P_ARP) printf("\nNetwork Layer Protocol: ARP\n");
	}
	return;
}

void ParseTcpHeader(unsigned char *packet, int len)
{
	struct ethhdr *eth_head;
	struct iphdr *ip_head;
	struct tcphdr *tcp_head;

	if(len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)))
	{
		eth_head=(struct ethhdr *)packet;
		if(ntohs(eth_head->h_proto)==ETH_P_IP)
		{
			ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
			if(ip_head->protocol==IPPROTO_TCP)
			{
				tcp_head=(struct tcphdr *)(packet+sizeof(struct ethhdr)+ip_head->ihl*4);

				printf("TCP Dest Port: %d\n", ntohs(tcp_head->dest));				
				printf("TCP Source Port: %d\n", ntohs(tcp_head->source));
				printf("Sequence_no : %u   Acknowledgement : %u\n",tcp_head->seq, tcp_head->ack_seq);
				printf("URG : %s   ACK : %s   PSH : %s   RST : %s   SYN : %s   FIN : %s   window : %u\n",tcp_head->urg?"yes":"no", tcp_head->ack?"yes":"no", tcp_head->psh?"yes":"no", tcp_head->rst?"yes":"no", tcp_head->syn?"yes":"no", tcp_head->fin?"yes":"no", ntohl(tcp_head->window)); 
			}
		}
	}
	return;
}	

void ParseUdpHeader(unsigned char *packet, int len)
{
	struct ethhdr *eth_head;
	struct iphdr *ip_head;
	struct udphdr *udp_head;

	if(len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)))
	{
		eth_head=(struct ethhdr *)packet;
		if(ntohs(eth_head->h_proto)==ETH_P_IP)
		{
			ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
			if(ip_head->protocol==IPPROTO_UDP)
			{
				udp_head=(struct udphdr *)(packet+sizeof(struct ethhdr)+ip_head->ihl*4);

				printf("UDP Dest Port: %d\n", ntohs(udp_head->dest));				
				printf("UDP Source Port: %d\n", ntohs(udp_head->source));
			}
		}
	}
	return;
}	

void ParseIcmpHeader(unsigned char *packet, int len)
{
	struct ethhdr *eth_head;
	struct iphdr *ip_head;
	struct icmphdr *icmp_head;

	if(len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)))
	{
		eth_head=(struct ethhdr *)packet;
		if(ntohs(eth_head->h_proto)==ETH_P_IP)
		{
			ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
			if(ip_head->protocol==IPPROTO_ICMP)
			{
				icmp_head=(struct icmphdr *)(packet+sizeof(struct ethhdr)+ip_head->ihl*4);

				printf("ICMP Head: %d\n", ntohs(icmp_head->code));				
				printf("ICMP Type: %d\n", ntohs(icmp_head->type));
			}
		}
	}
	return;
}

void ParseIpheader(unsigned char *packet, int len)
{
	struct ethhdr *eth_head;
	struct iphdr *ip_head;

	if(len>sizeof(struct ethhdr))
	{
		eth_head=(struct ethhdr *)packet;
	
		if(ntohs(eth_head->h_proto)==ETH_P_IP)
		{
			if(len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)))
			{
				ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
				printf("Dest IP Address: %s\n", (char *)inet_ntoa(ip_head->daddr));
				printf("Src IP Address: %s\n", (char *)inet_ntoa(ip_head->saddr));
				printf("version : %u  total_length : %u   id : %u   do_not_fragment : %s\n",ip_head->version, ntohs(ip_head->tot_len), ntohl(ip_head->id), (ip_head->frag_off & 0x4000)? "yes":"no");
				printf("more_fragments_following : %s   fragment_offset : %u   hops_to_live : %u\n",(ip_head->frag_off & 0x2000)? "yes":"no", (ip_head->frag_off & 0x1fff)*8, ip_head->ttl);
			}
		}
	}
	return;
}
		
void ParseArpHeader(unsigned char *packet, int len)
{
	struct ethhdr *eth_head;
	struct arphdr *arp=(struct arphdr *)(packet+sizeof(struct ethhdr));	
	int opcode = ntohs(arp->ar_op);
	char src_mac[20], dest_mac[20], src_ip[20], dest_ip[20];
	char* arp1 = (char*) arp + sizeof(struct arphdr);
	mac_to_string(arp1,src_mac);
	mac_to_string(arp1+10,dest_mac);
	ip_to_string(arp1+6,src_ip);
	ip_to_string(arp1+16,dest_ip);
	if(opcode==ARPOP_REQUEST)
		printf("ARP request from %s (%s) tell MAC address of %s\n",src_ip, src_mac, dest_ip);
	else if(opcode==ARPOP_RREQUEST)
		printf("RARP request from %s tell my IP address\n", src_mac);
	else if(opcode==ARPOP_REPLY)
		printf("ARP reply to %s (%s) tell MAC address of %s is %s\n",src_ip, src_mac, dest_ip, dest_mac);
	else if(opcode==ARPOP_RREPLY)
		printf("RARP reply to %s tell his IP address is %s\n", src_mac, src_ip);
}

void PrintInHex(char *msg, unsigned char *p, int len)
{
	printf("%s", msg);
	while(len--)
	{
		printf("%.2x ", *p);
		p++;
	}
	return;
}


void sniffer_init(PKT_OPT *packet_options)
{
	int i=0, j=0;
	char *device="eth0";
	packet_options->device=device;
	
	packet_options->promiscous=0;
	
	packet_options->packet_type.broadcast=0;
	packet_options->packet_type.multicast=0;
	packet_options->packet_type.host=0;
	packet_options->packet_type.outgoing=0;
	packet_options->packet_type.otherhost=0;
	
	for(i=0; i<10; i++)
		for(j=0; j<2; j++)	
			packet_options->packet_length[i][j]=0;
			
	packet_options->network_protocol=0;
	
	packet_options->transport_protocol.icmp=0;
	packet_options->transport_protocol.udp=0;
	packet_options->transport_protocol.tcp=0;
	
	packet_options->src_ip=NULL;
	packet_options->dest_ip=NULL;

	return;
}

void flag_init(PKT_PRT *packet_print_flags)
{
	packet_print_flags->arp=0;
	packet_print_flags->tcp=0;
	packet_print_flags->icmp=0;
	packet_print_flags->udp=0;
	return;	
}
