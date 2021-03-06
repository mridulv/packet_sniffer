################ PACKET SNIFFER ###################

Our packet sniffer takes some command line flags with some parameters.
Some flags have parameters, some do not. All flags are optional.
If any flag is not set then default values will be taken fr that flag. Flags could be given in any order.
When run without flags, sniffer will print all types of packets receiving at the 'eth0' interface.
Also, run the program with sudo or it will fail.

Note: The default interface is 'eth0', you'll have to change it if your default interface is something else.

flag : -i
parameters : interface name
description : to choose what interface you want to sniff, only one interface could be chosen at a time
examples : sniffer -i eth0, sniffer -i wlan0
default : eth0

flag : -z
parameters : none
description : sets sniffer in promiscuous mode. for some hardware interfaces the user may have to explicitly set the interface to default
by the command : $ ifconfig <interface_name> promisc
examples : sniffer -d eth0 -z, sniffer -z
default : off

flag : -p
parameters : packet type
description : to set the type of packet to sniff, valid packet types are "host", "broadcast", "multicast", "otherhost", "outgoing"
examples : sniffer -p broadcast:multicast, sniffer -p host:otherhost:broadcast
default : will sniff all type of packets

flag : -l
parameters : packet length
description : set specific packet lengths to sniff, you can also mention range of length using '-'
examples : sniffer -l 134:456-1234:900, sniffer -l 123:45678:900000
default : packets of at most maximum length 65535

flag : -n
parameters : network layer protocol
description : set network layer protocol packets you want to sniff, program supports two types - "ip", "arp"
examples : sniffer -n ip, sniffer -n ip:arp
default : both "ip" as well as "arp"

flag : -t
parameters : transport layer protocol
description : set transport layer protocol packets you want to sniff, program supports three types - "tcp", "udp", "icmp"
examples : sniffer -t udp:tcp, sniffer -t tcp:udp:icmp
default : all three "udp", "tcp", "icmp"

flag : -s
parameters : source ip address
description : set source ip of packets to sniff, only packets with specified ip(s) will be sniffed
examples : sniffer -s 172.24.185.0:172.24.8.219
default : all packets with any source ip will be sniffed

flag : -d
parameters : destination ip address
description : set destination ip of packets to sniff, only packets with specified ip(s) will be sniffed
examples : sniffer -d 172.24.6.78, sniffer -d 172.24.185.0:172.24.8.219
default : all packets with any destination ip will be sniffed

flag : -k
parameters : number of packets to sniff
description : set the number of packets to sniff, after the number of packets you mentioned is sniffed the program will halt, only
printing only those packets by filtering according to the other flags you may have set.
examples : sniffer -k 12345
default : program will keep sniffing packets for indefinitely

**********************************************************************
