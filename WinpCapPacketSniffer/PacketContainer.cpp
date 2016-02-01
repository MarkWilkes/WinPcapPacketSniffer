#include "PacketContainer.h"

PacketContainer::PacketContainer(pcap_pkthdr *hdr, u_char* dt){
	header = hdr;
	data = dt;
}

PacketContainer::~PacketContainer(){

}

void PacketContainer::print(){
	printf("\n Destination: %02x:%02x:%02x:%02x:%02x:%02x \n Source: %02x: %02x : %02x : %02x : %02x : %02x \n Type: %04hx",
		macDest[0], macDest[1], macDest[2], macDest[3], macDest[4], macDest[5],
		macSrc[0], macSrc[1], macSrc[2], macSrc[3], macSrc[4], macSrc[5], type);
}

void PacketContainer::processPacket(){
	//this will have to be changed to be wifi header
	ETHER_HDR* ethhdr = (ETHER_HDR *)data;

	for (int i = 0; i < 6; i++){
		macDest[i] = ethhdr->dest[i];
	}

	for (int i = 0; i < 6; i++){
		macSrc[i] = ethhdr->source[i];
	}

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