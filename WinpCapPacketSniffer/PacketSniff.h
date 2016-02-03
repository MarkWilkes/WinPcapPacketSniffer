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

	//setups up list of network device interfaces and instanciates the vector of packets
	int setupSniffer();
	//wraps up the sniffer, joining threads and clearing vector of packets and closes network devices
	void wrapupSniffer();
	//listens on specific device interface number opening it first (by default promiscuous)
	void beginListening(int dev);
	//listens on all devices opening them first (by default promiscuous)
	//makes a thread for each device will not stop the main threads control flow
	void beginListeningAll();
	//listens for traffic on an opened device
	//pushes any found packets to the back of the packetList
	void listen(pcap_t *device);

private:
	//returns the network device interface from a given number
	pcap_if_t * selectDevice(int devNumber);
	//return a device from a device interface that can listen to all traffic
	pcap_t * openDevicePromiscuous(pcap_if_t *device);
	//return a device from a device interface that can listen to all traffic
	pcap_t * openDeviceLocal(pcap_if_t *device);

private:
	//array of device interfaces
	pcap_if_t *networkDevices;
	//how many devices
	int numDevices;
	//packet list
	std::vector<PacketContainer *>* packetList;
	//thread list
	std::vector<std::thread> thr;
};

#endif