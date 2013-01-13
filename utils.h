#include "sniffer.h"

int parse_parameters(char* options_str);
int ParseIpHeader(unsigned char *packet, int len, char *src, char *dest);
void set_packet_type(PKT_OPT *packet_options, char *options);
void set_packet_length(PKT_OPT *packet_options, char *options);
void set_network_protocol(PKT_OPT *packet_options, char *options);
void set_transport_protocol(PKT_OPT *packet_options, char *options);
void set_promiscuous_mode(int raw, struct ifreq ifr);
int filter_packets_by_type(PKT_OPT *packet_options, int type, int packet_type_set);
void mac_to_string(unsigned char arr[6],char* str);
void ip_to_string(unsigned char arr[4], char* str);
void printData (const u_char * data , int Size);
void print_packet(PKT_PRT *print_flags, unsigned char *packet, int len);
void print_help();
