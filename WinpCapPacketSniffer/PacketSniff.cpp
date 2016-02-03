#include "PacketSniff.h"

//constructor for control flow object
PacketSniff::PacketSniff(){
	networkDevices = NULL;
	packetList = NULL;
}

//destructor for control flow object
PacketSniff::~PacketSniff(){
	if (packetList != NULL){
		delete packetList;
	}
}

//setup for control flow object
//prints network devices available to listen from
//instantiates the packet list
int PacketSniff::setupSniffer(){
	pcap_if_t *device;
	int numberOfDevices = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &networkDevices, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n Doesn't that suck.\n", errbuf);
		return -1;
	}

	//prints device interfaces and description as well as counts them
	for (device = networkDevices; device != NULL; device = device->next){
		printf("%d. %s", ++numberOfDevices, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n That's odd \n");
	}
	numDevices = numberOfDevices;
	//confirm we have at least 1 device
	if (numberOfDevices == 0){
		fprintf(stderr, "No devices found. What a shame.\n", errbuf);
		return -1;
	}

	//instantiates the packet list
	packetList = new std::vector<PacketContainer*>();

	return 0;
}

//loops through list device interfaces and returns the interface of that number
pcap_if_t * PacketSniff::selectDevice(int devNumber){
	pcap_if_t * device = networkDevices;
	for (int i = 0; i< devNumber - 1; device = device->next, i++);
	return device;
}

//opens device interface to listen to all the traffic and returns that device
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

//opens device interface to listen to all of your traffic and returns that device
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

//wrapup function. call this not the destructor or else you will leak and have run on threads
void PacketSniff::wrapupSniffer(){
	while (!thr.empty()){
		thr.at(0).join();
	}

	pcap_freealldevs(networkDevices);
	packetList->clear();
	delete this;
}

//listen to a device number
//will not block control flow
//will open a thread
void PacketSniff::beginListening(int dev){
	pcap_t * opened = openDevicePromiscuous(selectDevice(dev));
	if (opened == NULL){
		return;
	}
	thr.push_back(std::thread(&PacketSniff::listen, this, opened));
}

//blocks control flow of thread calls this
//listens for packets and puts them into packet list then prints them
void PacketSniff::listen(pcap_t *openedDevice){
	int result;
	PacketContainer *p;
	struct pcap_pkthdr *header;
	u_char * data;
	while ((result = pcap_next_ex(openedDevice, &header, (const u_char**)&data)) >= 0){
		//no packet seen let's keep going
		if (result == 0){
			continue;
		}
		//make a packetcontainer
		p = new PacketContainer(header, data);
		//you must process it to parse the headers and data
		p->processPacket();
		//print it's relevant information to console
		p->print();
		//put it in the list
		packetList->push_back(p);
	}
}

//listen to all devices
//will not block control flow
//will open a thread
void PacketSniff::beginListeningAll(){
	pcap_if_t * device;
	pcap_t * opened;
	thr = std::vector<std::thread>();
	for (device = networkDevices; device != NULL; device = device->next){
		//sanity check to make sure we don't get a null pointer
		if (device == NULL) break;
		//open device to all traffic
		opened = openDevicePromiscuous(device);
		//make sure it is opened
		if (opened == NULL) continue;
		//keep a link to the thread when we open it.
		thr.push_back(std::thread(&PacketSniff::listen,this,opened));
	}
}