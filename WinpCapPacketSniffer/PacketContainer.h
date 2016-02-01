#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

#ifndef PacketCon
#define PacketCon
/*
0x00	= unsigned char		= 1 bytes
0x0000	= unsigned short	= 2 bytes
0x00000000 = unsigned int	= 4 bytes
*/
class PacketContainer{
public:

	typedef struct ethernet_header{
		u_char dest[6];
		u_char source[6];
		u_short type;
	}   ETHER_HDR, ETHERHeader;

	PacketContainer(pcap_pkthdr *header, u_char* data);
	~PacketContainer();

	void print();
	void processPacket();

private:
	struct pcap_pkthdr *header;
	u_char *data;
	u_char macDest[6];	//print type is 6 zero pad up to 2 unsigned hex = 02x
	u_char macSrc[6];	//print type is 6 zero pad up to 2 unsigned hex = 02x
	u_short type;	//print type is zero pad up to 4 digits short unsigned hex = 04hx
};

#endif