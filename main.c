#include "sniffer.h"

main(int argc, char **argv)
{
	int raw; unsigned char packet_buffer[PACKET_BUFFER_SIZE]; int packet_len;
	int packets_to_sniff=-1;
	
	struct ifreq ifr;

	int i=1, j=0, k=0; char flag; int set=0;
	int packet_length_set=0;
	int packet_type_set=0;
	int packet_network_protocol_set=0;
	int packet_transort_protocol_set=0;
	int packet_src_ip_set=0;
	int packet_dest_ip_set=0;
	
	PKT_OPT *packet_options=(PKT_OPT *)malloc(sizeof(PKT_OPT));
	PKT_PRT *packet_print_flags=(PKT_PRT *)malloc(sizeof(PKT_PRT));
	
	sniffer_init(packet_options);
	
	while(i <= argc-1)
	{
		flag = argv[i++][1];
		switch(flag)
		{
			case 'i': packet_options->device=argv[i++]; break;
			case 'z': packet_options->promiscous=1; break;
			case 'p': set_packet_type(packet_options, argv[i++]); packet_type_set=1; break;
			case 'l': set_packet_length(packet_options, argv[i++]); packet_length_set=1; break;
			case 'n': set_network_protocol(packet_options, argv[i++]);  packet_network_protocol_set=1;  break;
			case 't': set_transport_protocol(packet_options, argv[i++]); packet_transort_protocol_set=1; break;			
			case 's': packet_options->src_ip=argv[i++]; packet_src_ip_set=1; break;
			case 'd': packet_options->dest_ip=argv[i++]; packet_dest_ip_set=1; break;
			case 'k': packets_to_sniff = atoi(argv[i++]); break;
			default : print_help();  return -1;
		}
	}																																									
	struct sockaddr_ll packet_info;
	int packet_info_size=sizeof(packet_info);
	
	struct ethhdr *eth_head;
	struct arphdr* arp_head;
	struct iphdr *ip_head;
	struct tcphdr *tcp_head;
	struct udphdr *udp_head;
	struct icmphdr *icmp_head;

	raw=CreateRawSocket(ETH_P_ALL);
	ifr=BindSocketToInterface(packet_options->device, raw, ETH_P_ALL);

	if(packet_options->promiscous==1) set_promiscuous_mode(raw, ifr);
	if(packet_length_set==0) {packet_options->packet_length[0][0]=0; packet_options->packet_length[0][1]=PACKET_BUFFER_SIZE;} 
	while(packets_to_sniff--)
	{													
		flag_init(packet_print_flags);
		set=0;
		if((packet_len=recvfrom(raw, packet_buffer, PACKET_BUFFER_SIZE, 0, (struct sockaddr *)&packet_info, &packet_info_size))==-1)
		{
			perror("\nERROR: Recv From Error: \n");
			exit(-1);
		}
		else
		{
			
			for(j=0;j<PACKET_LENGTH_INSTANCE; j++)
			{
				if(packet_len>=packet_options->packet_length[j][0] && packet_len<=packet_options->packet_length[j][1] && set==0)
				{
					if(filter_packets_by_type(packet_options, packet_info.sll_pkttype, packet_type_set))
					{
						if(packet_len>=sizeof(struct ethhdr))
						{
							eth_head=(struct ethhdr *)packet_buffer;

							
							if(ntohs(eth_head->h_proto)==ETH_P_IP && (packet_options->network_protocol==0 || packet_options->network_protocol==1))
							{
								if(packet_len>=(sizeof(struct ethhdr)+sizeof(struct iphdr)))
								{
									
									ip_head=(struct iphdr *)(packet_buffer+sizeof(struct ethhdr));
									if(ParseIpHeader(packet_buffer, packet_len, packet_options->src_ip, packet_options->dest_ip))
									{
										if((ip_head->protocol==IPPROTO_TCP && packet_options->transport_protocol.tcp==1) || packet_transort_protocol_set==0 )
										{
											tcp_head=(struct tcphdr *)(packet_buffer+sizeof(struct ethhdr)+ip_head->ihl*4);
											packet_print_flags->tcp=1;
										}
										else if((ip_head->protocol==IPPROTO_UDP && packet_options->transport_protocol.udp==1) || packet_transort_protocol_set==0)
										{
											udp_head=(struct udphdr *)(packet_buffer+sizeof(struct ethhdr)+ip_head->ihl*4);
											packet_print_flags->udp=1;
										}
										else if((ip_head->protocol==IPPROTO_ICMP && packet_options->transport_protocol.icmp==1) || packet_transort_protocol_set==0)
										{
											icmp_head=(struct icmphdr *)(packet_buffer+sizeof(struct ethhdr)+ip_head->ihl*4);
											packet_print_flags->icmp=1;
										}
									}
								}
							}
							if(ntohs(eth_head->h_proto)==ETH_P_ARP && (packet_options->network_protocol==2 || packet_options->network_protocol==0))
							{
								if(packet_len>=(sizeof(struct ethhdr)+sizeof(struct arphdr)))
								{
									arp_head=(struct arphdr *)(packet_buffer+sizeof(struct ethhdr));
									packet_print_flags->arp=1;
								}
							}							
							print_packet(packet_print_flags, packet_buffer, packet_len);
						}
					}
					set=1;
				}
			}
		}
	}
	return;
}
