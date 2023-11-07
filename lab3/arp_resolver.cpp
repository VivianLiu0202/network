#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <iostream>
#include <netinet/tcp.h>
#include <string>
#include <memory> // for std::unique_ptr
#include <stdexcept> // for runtime_error
#include <array>
using namespace std;

#pragma pack(1)
struct ARP_HEADER {
    u_short HardwareType; // 硬件类型
    u_short ProtocolType; // 协议类型
    u_char HardwareSize; // 硬件地址长度
    u_char ProtocolSize; // 协议地址长度
    u_short Operation; // 操作类型
    u_char SenderHardwareAddress[6]; // 发送方MAC地址
    u_char SenderProtocolAddress[4]; // 发送方IP地址
    u_char TargetHardwareAddress[6]; // 目的MAC地址
    u_char TargetProtocolAddress[4]; // 目标IP地址
};
#pragma pack()   //恢复缺省对齐方式

void send_arp_request(pcap_t *adhandle,in_addr local_ip,u_char *local_mac,in_addr target_ip){
	u_char packet[sizeof(ether_header) + sizeof(ARP_HEADER)]; // 数据包内容，大小为以太网帧头部 + ARP帧头部
    // 强转分离出以太网帧头部和ARP帧头部
	ether_header *eth = (ether_header *)packet;
    ARP_HEADER *arp = (ARP_HEADER *)(packet + sizeof(ether_header));

	//填充以太网帧的头部
	for(int i=0;i<6;i++){
		eth->ether_dhost[i] = 0xff;
		eth->ether_shost[i] = local_mac[i];
	}
	eth->ether_type = htons(0x0806);

	//arp头
	arp->HardwareType = htons(1); // 1代表链路层为Ethernet
	arp->ProtocolType = htons(0x0800);	// ARP上层协议为IP 
	arp->HardwareSize = 6; //48位MAC
	arp->ProtocolSize = 4; //32为IP
	arp->Operation = htons(0x0001); //1代表此包为ARP请求
	for(int i=0;i<6;i++){
		arp->SenderHardwareAddress[i] = local_mac[i];
		arp->TargetHardwareAddress[i] = 0x00;
	}
	memcpy(arp->SenderProtocolAddress,&local_ip.s_addr,4);
	memcpy(arp->TargetProtocolAddress,&target_ip.s_addr,4);

	int result = pcap_sendpacket(adhandle,packet,sizeof(packet));
	if(result == -1){
		printf("发送失败!\n");
	}
	else if(result == 0){
		printf("发送成功！正在等待ARP响应！\n");
	}

}

bool receive_arp_response(pcap_t *adhandle, in_addr target_ip, u_char *target_mac){
	struct pcap_pkthdr *header;
	const u_char *packet;
	while(pcap_next_ex(adhandle,&header,&packet) >= 0){
		ether_header *eth = (ether_header *)packet;
		if(ntohs(eth->ether_type) !=0x0806) continue;
		ARP_HEADER *arp = (ARP_HEADER *)(packet+sizeof(ether_header));
		if(ntohs(arp->Operation) == 0x0002 && memcmp(arp->SenderProtocolAddress,&target_ip.s_addr,4) == 0){
			memcpy(target_mac,arp->SenderHardwareAddress,6);
			return true;
		}
	}
	return false;
}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int main(){
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 1;
    }
	int i = 0;
	for (dev = alldevs; dev; dev = dev->next,++i){
		printf("设备%d: %s\n", i, dev->name);
        std::string command = "system_profiler SPNetworkDataType | grep -A1 " + std::string(dev->name);
        std::string output = exec(command.c_str());
        if(output.length() == 0) std::cout << "Description: " << "No description" << std::endl;
        else std::cout << "Description: " << std::endl << output;
	}

	if (i == 0)
	{
		printf("\n没有发现网络接口,请检查设备\n");
		return 0;
	}
	printf("\n输入要选择打开的网卡号 (0-%d):\t", i-1);
    int devIndex;
	scanf("%d",&devIndex);
	if (devIndex < 0 || devIndex >= i) {
		printf("\n网卡号超出范围\n");
		pcap_freealldevs(alldevs); //释放设备列表
		return 0;
	}
    for (dev = alldevs, i = 0; i < devIndex; dev = dev->next, ++i) ;

	// 获取本地IP和掩码
	char ipString[INET_ADDRSTRLEN]; // 用于存储IP地址字符串
    char maskString[INET_ADDRSTRLEN]; // 用于存储掩码地址字符串
    const char *ipSrc; // 指向转换后的IP字符串
    const char *maskSrc; // 指向转换后的掩码字符串
    pcap_addr_t *d;
	for(d = dev->addresses;d!=NULL;d=d->next){
		if (d->addr->sa_family == AF_INET){
			if (d->addr) {
				ipSrc = inet_ntop(AF_INET, &((struct sockaddr_in*)d->addr)->sin_addr, ipString, sizeof(ipString));
				printf("本地IPv4地址为: %s\n", ipSrc);
			}
			if (d->netmask) {
				maskSrc = inet_ntop(AF_INET, &((struct sockaddr_in*)d->netmask)->sin_addr, maskString, sizeof(maskString));
				printf("IPv4掩码为: %s\n", maskSrc);
				printf("hello!");
			}
			break;
    	}
	}

    pcap_t *adhandle= pcap_open_live(dev->name, 65536, 1, 2000, errbuf);
	if (adhandle == NULL) {
		printf("\n无法打开适配器!请检查设备\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	in_addr local_ip;
	local_ip.s_addr = inet_addr(ipSrc);


	//发送ARP包来获取本机MAC地址
	u_char myMAC[6];
	uint8_t sendbuf[42];
	ether_header eth;
	ARP_HEADER arp;
	pcap_pkthdr *pkth;
	const uint8_t* pktdata;
	memset(eth.ether_dhost,(uint8_t)0xff,6);
	memset(eth.ether_shost,0x00,6); //源MAC随便写
	eth.ether_type=htons(0x0806);

	arp.HardwareType=htons(1);
	arp.ProtocolType=htons(0x0800);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = htons(1);

	memset(arp.SenderHardwareAddress,0x00,6);
	memset(arp.TargetHardwareAddress,(uint8_t)0x00,6);
	inet_pton(AF_INET, ipSrc, &arp.SenderProtocolAddress);
	inet_pton(AF_INET, ipSrc, &arp.TargetProtocolAddress);

	memset(sendbuf,0,sizeof(sendbuf));
	memcpy(sendbuf,&eth,sizeof(eth));
	memcpy(sendbuf+sizeof(eth),&arp,sizeof(arp));

	if(pcap_sendpacket(adhandle,sendbuf,42)!=0){
		printf("发送ARP请求失败!\n");
		return 0;
	}
	printf("发送ARP请求成功!\n");

	while (1)
	{
		int result = pcap_next_ex(adhandle, &pkth, &pktdata);
		if(result < 0 ){
			printf("捕获数据包发生错误\n");
			return 0;
		}
		else if(result == 0){
			printf("没有捕获到数据包\n");
			break;
		}
		else{
			unsigned char *temp=NULL;
			ether_header *neweth = (ether_header*)(pktdata);
			ARP_HEADER *newarp = (ARP_HEADER *)(pktdata+sizeof(ether_header));
			// printf("%x\n",ntohs(neweth->ether_type));
			// printf("%x\n",ntohs(newarp->Operation));
			// for(int i=0;i<4;i++){
			// 	printf("%02x",newarp->TargetProtocolAddress[i]);
			// }
			// printf("\n");
			// for(int i=0;i<4;i++){
			// 	printf("%02x",arp.SenderProtocolAddress[i]);
			// }
			// memcpy(temp,newarp->TargetProtocolAddress,4);
			// printf("%s\n",temp);
			// printf("\n");
			if(ntohs(neweth->ether_type) == 0x0806 && ntohs(newarp->Operation) == 0x0002 
				&& memcmp(newarp->TargetProtocolAddress,arp.SenderProtocolAddress,4) == 0){
				printf("本机的MAC地址如下:\n");
				for(int i=0;i<6;i++){
					myMAC[i] = newarp->TargetHardwareAddress[i];
					printf("%02x",myMAC[i]);
					if(i<5) printf(":");
				}
				printf("\n");
				break;
			}
		}
	}

	while(1){
		printf("请输入目标IP地址:\n");
		char target_ip_str[20];
		scanf("%s",target_ip_str);
		if(strcmp(target_ip_str,"exit") == 0) break;
		in_addr target_ip;
		inet_pton(AF_INET,target_ip_str,&target_ip);
		u_char target_mac[6];
		send_arp_request(adhandle,local_ip,myMAC,target_ip);
		if(receive_arp_response(adhandle,target_ip,target_mac)){
			printf("目标MAC地址如下:\n");
			for(int i=0;i<6;i++){
				printf("%02x",target_mac[i]);
				if(i<5) printf(":");
			}
			printf("\n");
		}
		else{
			printf("未收到ARP响应!\n");
		}
	}
	pcap_close(adhandle);
	pcap_freealldevs(alldevs);
	return 0;
}