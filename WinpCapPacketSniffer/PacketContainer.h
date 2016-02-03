#include <stdint.h>
#include <stdio.h>
//include pcap after everything else because of linker stuff
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
	//link layer ethernet header structure
	typedef struct ethernet_header{
		u_char dest[6]; //Mac destination
		u_char source[6];	//Mac source
		u_short type;	//IP type
	}   ETHER_HDR, ETHERHeader;

	//constructor has to take the link layer header and payload
	PacketContainer(pcap_pkthdr *header, u_char* data);
	~PacketContainer();

	void print();	//prints out the formatted header data we have collected
	void processPacket();	//processes the data buffer into the private packet variables

private:
	struct pcap_pkthdr *header;	//link layer packet header
	u_char *data;		//char arrary of the packet payload
	u_char macDest[6];	//print type is 6 zero pad up to 2 unsigned hex = 02x
	u_char macSrc[6];	//print type is 6 zero pad up to 2 unsigned hex = 02x
	u_short type;	//print type is zero pad up to 4 digits short unsigned hex = 04hx
};

#endif