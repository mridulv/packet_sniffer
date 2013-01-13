#include "utils.h"

char parameters[10][20];

int parse_parameters(char* options_str)
{
	if(options_str==NULL) return 0;
	int i=0,count=0,j=0;
	while(options_str[i]!='\0')
	{
		if(options_str[i]==':') 
		{
			parameters[count][j]='\0';
			j=0;	
			count++;
		}
		else parameters[count][j++] = options_str[i];
		i++;
	}
	parameters[count][j]='\0';
	return count+1;
}

int ParseIpHeader(unsigned char *packet, int len, char *src, char *dest)
{
	struct ethhdr *eth_head;
	struct iphdr *ip_head;
	int res_src=0, res_dest=0;
	int i=0, j=0;
	int src_match=0;
	int dest_match=0;
															
	if(src==NULL && dest==NULL) return 1;
														
	if(len>sizeof(struct ethhdr))
	{
		eth_head=(struct ethhdr *)packet;
				
		if(ntohs(eth_head->h_proto)==ETH_P_IP)
		{ 
			if(len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)))
			{																			
				ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
											
				res_src=parse_parameters(src);
				if(res_src>0)
				{									
					for(i=0; i<res_src; i++)
					{
						if (!strcmp((char *)inet_ntoa(ip_head->saddr), parameters[i])) {src_match=1; break;}
					}
				}
				else
				{
					src_match=1;
				}
				
				res_dest=parse_parameters(dest);
				if(res_dest>0)
				{
					for(i=0; i<res_dest; i++)
					{
						if (!strcmp((char *)inet_ntoa(ip_head->daddr), parameters[i])) {dest_match=1; break;}
					}
				}
				else
				{
					dest_match=1;
				}
				if(src_match==1 && dest_match==1)
				{
					return 1;
				}
				else return 0;
			}
		}
	}
	return 0;
}

void set_packet_type(PKT_OPT *packet_options, char *options)
{
	int res=parse_parameters(options);
	int i=0;
	while(res--)
	{
		if(!strcmp(parameters[i], "broadcast")) packet_options->packet_type.broadcast=1;
		else if(!strcmp(parameters[i], "multicast")) packet_options->packet_type.multicast=1;
		else if(!strcmp(parameters[i], "host")) packet_options->packet_type.host=1;
		else if(!strcmp(parameters[i], "otherhost")) packet_options->packet_type.otherhost=1;
		else if(!strcmp(parameters[i], "outgoing")) packet_options->packet_type.outgoing=1;
		else {printf("\nERROR: Incorrect Packet Type Option\n"); exit(-1);}
		i++;
	}	
}

void set_packet_length(PKT_OPT *packet_options, char *options)
{
	int res=parse_parameters(options);
	int i=0,j=0,sum=0;
	int num=0;
	char temp;
	while(res--)
	{
		for(j=0;j<strlen(parameters[i]);j++)
		{
			if(parameters[i][j] !='-')
			{
				sum=sum*10+parameters[i][j]-'0';
			}
			else
			{
				packet_options->packet_length[i][num]=sum;
				num++;
				sum=0;
			}
		}
		packet_options->packet_length[i][num]=sum;
		if(num==0) packet_options->packet_length[i][num+1]=sum;
		sum=0; i++; num=0;
	}
}

void set_network_protocol(PKT_OPT *packet_options, char *options)
{
	int res=parse_parameters(options);
	if(res==1 && !strcmp(parameters[0],"ip")) packet_options->network_protocol=1;
	else if(res==1 && !strcmp(parameters[0],"arp")) packet_options->network_protocol=2;
	else if(res==2 && ((!strcmp(options,"ip:arp"))||(!strcmp(options,"arp:ip")))) packet_options->network_protocol=0;
	else
	{
		printf("\nERROR: Incorrect Network Protocol Options\n");
		exit(-1);
	}
}

void set_transport_protocol(PKT_OPT *packet_options, char *options)
{
	int res=parse_parameters(options);
	int i=0;
	while(res--)
	{
		if (!strcmp(parameters[i], "udp")) packet_options->transport_protocol.udp=1;
		else if (!strcmp(parameters[i], "tcp")) packet_options->transport_protocol.tcp=1;
		else if (!strcmp(parameters[i], "icmp")) packet_options->transport_protocol.icmp=1;
		else {printf("\nERROR: Packet Transport Protocol options Incorrect\n"); exit(-1);}
		i++;
	}
}

void set_promiscuous_mode(int raw, struct ifreq ifr)
{
	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) 
	{ 
		close(raw); 
		perror("\nError: Setting Promiscuous mode\n"); 
	}
}

int filter_packets_by_type(PKT_OPT *packet_options, int type, int packet_type_set)
{
	if(packet_type_set==0) return 1;
	else
	{
		if(packet_options->packet_type.broadcast==1 && type==PACKET_BROADCAST)	return 1;
		if(packet_options->packet_type.host==1 && type==PACKET_HOST)			return 1;
		if(packet_options->packet_type.otherhost==1 && type==PACKET_OTHERHOST)	return 1;
		if(packet_options->packet_type.outgoing==1 && type==PACKET_OUTGOING)	return 1;
		if(packet_options->packet_type.multicast==1 && type==PACKET_MULTICAST)	return 1;	
	}
	return 0;
}


void mac_to_string(unsigned char arr[6],char* str)
{
	sprintf(str,"%.2x.%.2x.%.2x.%.2x.%.2x.%.2x",arr[0],arr[1],arr[2],arr[3],arr[4],arr[5]);
}

void ip_to_string(unsigned char arr[4], char* str)
{
	sprintf(str,"%u.%u.%u.%u",arr[0],arr[1],arr[2],arr[3]);
}


void printData (const u_char * data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)
		{
			printf("         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					printf("%c",(unsigned char)data[j]);
				
				else printf(".");
			}
			printf("\n");
		} 
		if(i%16==0) printf("   ");
		printf(" %02X",(unsigned int)data[i]);	
		if( i==Size-1)
		{
			for(j=0;j<15-i%16;j++) printf("   ");
			
			printf("         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
				else printf(".");
			}
			printf("\n" );
		}
	}
}


void print_packet(PKT_PRT *print_flags, unsigned char *packet, int len)
{
	struct ethhdr *eth_head;
	struct arphdr* arp_head;
	struct iphdr *ip_head;
	struct tcphdr *tcp_head;
	struct udphdr *udp_head;
	struct icmphdr *icmp_head;
	
	eth_head=(struct ethhdr *)packet;
	
	if(print_flags->arp==1)
	{
		arp_head=(struct arphdr *)(packet+sizeof(struct ethhdr));
		printf("########################## Start Of Packet (%d Bytes) ##########################\n\n", len);
		printf("-------------------- Start Of Ethernet Header (14 Bytes) ---------------------\n");
		printf("\n");
		ParseEthernetHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of Ethernet Header --------------------");
		printf("\n");
		printf("-------------------- Start Of ARP Header --------------------\n");
		printf("\n");
		ParseArpHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of ARP Header --------------------");
		printf("\n");printf("\n");
		printf("########################## End Of Packet ##################################\n\n\n\n");
	}
	else if(print_flags->tcp==1)
	{
		ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
		tcp_head=(struct tcphdr *)(packet+sizeof(struct ethhdr)+ip_head->ihl*4);
		
		printf("########################## Start Of Packet (%d Bytes) ##########################\n\n", len);
		printf("-------------------- Start Of Ethernet Header (14 Bytes) --------------------\n");
		printf("\n");
		ParseEthernetHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of Ethernet Header --------------------");
		printf("\n");
		printf("-------------------- Start Of IP Header (%d Bytes) --------------------\n", ip_head->ihl*4);
		printf("\n");
		ParseIpheader(packet, len);
		printf("\n");
		printf("-------------------- End Of IP Header --------------------");
		printf("\n");
		printf("-------------------- Start Of TCP Header (%u Bytes) --------------------\n", tcp_head->doff*4);
		printf("\n");
		ParseTcpHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of TCP Header --------------------");	
		printf("\n");
		printf("-------------------- Data Payload (%d Bytes) --------------------\n\n", len-sizeof(struct ethhdr)-ip_head->ihl*4-tcp_head->doff*4);
		printData((u_char *)(tcp_head+tcp_head->doff*4), len-sizeof(struct ethhdr)-ip_head->ihl*4-tcp_head->doff*4);
		printf("\n\n");
		printf("########################## End Of Packet ##################################\n\n\n\n");
	}
	else if(print_flags->udp==1)
	{
		ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
		udp_head=(struct udphdr *)(packet+sizeof(struct ethhdr)+ip_head->ihl*4);
		
		printf("########################## Start Of Packet (%d Bytes) ##########################\n\n", len);
		printf("-------------------- Start Of Ethernet Header (14 Bytes) --------------------\n");
		printf("\n");
		ParseEthernetHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of Ethernet Header --------------------");
		printf("\n");
		printf("-------------------- Start Of IP Header (%d Bytes) --------------------\n", ip_head->ihl*4);
		printf("\n");
		ParseIpheader(packet, len);
		printf("\n");
		printf("-------------------- End Of IP Header --------------------");
		printf("\n");
		printf("-------------------- Start Of UDP Header (%u Bytes) --------------------\n", sizeof(struct udphdr));
		printf("\n");
		ParseUdpHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of UDP Header --------------------");			
		printf("\n");
		printf("-------------------- Data Payload (%d Bytes) --------------------\n\n", len-sizeof(struct ethhdr)-ip_head->ihl*4-sizeof(struct udphdr));
		printData(packet+sizeof(struct ethhdr) + ip_head->ihl*4 + sizeof(struct udphdr), len-sizeof(struct ethhdr)-ip_head->ihl*4-sizeof(struct udphdr));
		printf("\n\n");
		printf("########################## End Of Packet ##################################\n\n\n\n");
	}
	else if(print_flags->icmp==1)
	{
		ip_head=(struct iphdr *)(packet+sizeof(struct ethhdr));
		icmp_head=(struct icmphdr *)(packet+sizeof(struct ethhdr)+ip_head->ihl*4);
		
		printf("########################## Start Of Packet (%d Bytes) ##########################\n\n", len);
		printf("-------------------- Start Of Ethernet Header (14 Bytes) --------------------\n");
		printf("\n");
		ParseEthernetHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of Ethernet Header --------------------");
		printf("\n");
		printf("-------------------- Start Of IP Header (%d Bytes) --------------------\n", ip_head->ihl*4);
		printf("\n");
		ParseIpheader(packet, len);
		printf("\n");
		printf("-------------------- End Of IP Header --------------------");
		printf("\n");
		printf("-------------------- Start Of ICMP Header (%d Bytes) -------------------\n", sizeof(struct icmphdr));
		printf("\n");
		ParseIcmpHeader(packet, len);
		printf("\n");
		printf("-------------------- End Of ICMP Header --------------------");		
		printf("\n");
		printf("-------------------- Data Payload (%d Bytes) --------------------\n\n", len-(sizeof(struct ethhdr)+ip_head->ihl*4+sizeof(struct icmphdr)));
		printData(packet+sizeof(struct ethhdr)+ip_head->ihl*4+sizeof(struct icmphdr), len-(sizeof(struct ethhdr)+ip_head->ihl*4+sizeof(struct icmphdr)));
		printf("\n\n");
		printf("########################## End Of Packet ##################################\n\n\n\n");
	}
}


void print_help()
{
		printf("\n\nUsage: sniffer [OPTION] [OPTION] [OPTION]... \nSniffs all the packet on a network\n\n ");
		printf("\t -i \t: Sets the network adapter type interface, e.g eth0,wlan0,etc.... \n");
		printf("\t -z \t: Sets the promisc bit of the adapter\n");
		printf("\t -p \t: Used for the packet type, e.g host, outgoing,etc....\n");
		printf("\t -l \t: Sets the multiple range of the packet lengths to capture, e.g 12-156:34:56....\n");
		printf("\t -n \t: Choose the network protocol among IP or ARP or both, e.g ip:arp, ip....\n");
		printf("\t -t \t: Choose the transport protocol among UDP,TCP or ICMP, e.g as above.... \n");
		printf("\t -s \t: Specifies the source addresses you want to sniff\n");
		printf("\t -d \t: Specifies the destination addresses you want to sniff\n");
		printf("\t -k \t: Number of packets you want to sniff\n");
		printf("For more details refer to help.txt\n\n\n");
}
