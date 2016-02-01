#include "PacketSniff.h"

PacketSniff::PacketSniff(){
	networkDevices = NULL;
	packetList = NULL;
}

PacketSniff::~PacketSniff(){
	if (packetList != NULL){
		delete packetList;
	}
}

int PacketSniff::setupSniffer(){
	pcap_if_t *device;
	int numberOfDevices = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &networkDevices, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n Doesn't that suck.\n", errbuf);
		return -1;
	}

	for (device = networkDevices; device != NULL; device = device->next){
		printf("%d. %s", ++numberOfDevices, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n That's odd \n");
	}
	numDevices = numberOfDevices;
	if (numberOfDevices == 0){
		fprintf(stderr, "No devices found. What a shame.\n", errbuf);
		return -1;
	}

	packetList = new std::vector<PacketContainer*>();

	return 0;
}

pcap_if_t * PacketSniff::selectDevice(int devNumber){
	pcap_if_t * device = networkDevices;
	for (int i = 0; i< devNumber - 1; device = device->next, i++);
	return device;
}

pcap_t * PacketSniff::openDevicePromiscuous(pcap_if_t *device){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * openedDevice;
	if ((openedDevice = pcap_open(device->name,
		100,PCAP_OPENFLAG_PROMISCUOUS,20,NULL,errbuf)) == NULL){
		fprintf(stderr, "\nError opening adapter\n");
		return NULL;
	}

	return openedDevice;
}

pcap_t * PacketSniff::openDeviceLocal(pcap_if_t *device){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* openedDevice;
	if ((openedDevice = pcap_open(device->name,
		100, PCAP_OPENFLAG_NOCAPTURE_LOCAL, 20, NULL, errbuf)) == NULL){
		fprintf(stderr, "\nError opening adapter\n");
		return NULL;
	}

	return openedDevice;
}

void PacketSniff::wrapupSniffer(){
	while (!thr.empty()){
		thr.at(0).join();
	}

	pcap_freealldevs(networkDevices);
	packetList->clear();
	delete this;
}

void PacketSniff::beginListening(int dev){
	pcap_t * res = openDevicePromiscuous(selectDevice(dev));
	if (res == NULL){
		return;
	}
}

void PacketSniff::listen(pcap_t *openedDevice){
	//pcap_t* openedDevice = (pcap_t *)open;
	int res;
	PacketContainer *p;
	struct pcap_pkthdr *header;
	u_char * data;
	while ((res = pcap_next_ex(openedDevice, &header, (const u_char**)&data)) >= 0){
		if (res == 0){
			// Timeout elapsed
			continue;
		}
		p = new PacketContainer(header, data);
		p->processPacket();
		p->print();
		packetList->push_back(p);
	}
}

void PacketSniff::beginListeningAll(){
	pcap_if_t * device;
	pcap_t * opened;
	thr = std::vector<std::thread>();
	for (device = networkDevices; device != NULL; device = device->next){
		if (device == NULL) break;
		opened = openDevicePromiscuous(device);
		if (opened == NULL) continue;
		thr.push_back(std::thread(&PacketSniff::listen,this,opened));
	}
}