#include "PacketContainer.h"

PacketContainer::PacketContainer(pcap_pkthdr *hdr, u_char* dt){
	header = hdr;
	data = dt;
}

PacketContainer::~PacketContainer(){

}

void PacketContainer::print(){
	//print formatting is great right now will be switched to cout stream later
	printf("\n Destination: %02x:%02x:%02x:%02x:%02x:%02x \n Source: %02x:%02x:%02x:%02x:%02x:%02x \n Type: %04hx",
		macDest[0], macDest[1], macDest[2], macDest[3], macDest[4], macDest[5],
		macSrc[0], macSrc[1], macSrc[2], macSrc[3], macSrc[4], macSrc[5], type);
}

void PacketContainer::processPacket(){
	//the datalink layer header will have to be changed to be wifi header once we get to sniffing 802.11 headers

	//sort out the ethernet header from the data.
	ETHER_HDR* ethhdr = (ETHER_HDR *)data;

	//mac address parsing for destination
	for (int i = 0; i < 6; i++){
		macDest[i] = ethhdr->dest[i];
	}

	//mac address parsing for source
	for (int i = 0; i < 6; i++){
		macSrc[i] = ethhdr->source[i];
	}

	//using network to host conversion of char indexing for types find the application layer type
	switch (ntohs(ethhdr->type)){
	case(0x0800) :
		//ipv4
		type = 0x0800;
		break;
	case(0x86DD) :
		//ipv6
		type = 0x86DD;
		break;
	}
	
}