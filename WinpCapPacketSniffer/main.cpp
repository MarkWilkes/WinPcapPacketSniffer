
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
	//by default it will listen promiscuously
	pSniff->beginListeningAll();
	//pause the main thread so it doesn't go into clean up while the listening threads have just started up.
	system("pause");
	//cleanup function
	pSniff->wrapupSniffer();

	return 0;
}