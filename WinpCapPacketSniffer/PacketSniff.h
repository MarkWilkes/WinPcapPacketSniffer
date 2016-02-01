
#include <vector>
#include <thread>
#include <pcap.h>
#pragma comment(lib, "ws2_32.lib")
#include <WinSock2.h>

#include "PacketContainer.h"

#ifndef Sniffer
#define Sniffer

class PacketSniff{
public:
	PacketSniff();
	~PacketSniff();

	int setupSniffer();
	void wrapupSniffer();
	void beginListening(int dev);
	void beginListeningAll();
	void listen(pcap_t *device);

private:
	pcap_if_t * selectDevice(int devNumber);
	pcap_t * openDevicePromiscuous(pcap_if_t *device);
	pcap_t * openDeviceLocal(pcap_if_t *device);
	std::vector<std::thread> thr;

private:
	pcap_if_t *networkDevices;
	int numDevices;
	std::vector<PacketContainer *>* packetList;
};

#endif