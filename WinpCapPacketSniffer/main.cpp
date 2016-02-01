
#include "PacketSniff.h"
#include <pcap.h>

int main(){
	//Control Flow object
	PacketSniff* pSniff = new PacketSniff();
	//setup the Packet Sniffer
	if (pSniff->setupSniffer() == -1){
		return -1;
	}
	//Listen on all devices
	pSniff->beginListeningAll();
	system("pause");
	pSniff->wrapupSniffer();

	return 0;
}