#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h> // in_addr
#include "Packet.h"

uint16_t checksum(struct ip_header* iphdr){
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)iphdr;
    iphdr->Checksum = 0;//将校验和字段置为0
    // 将IP首部中的每16位相加
    for(int i = 0; i < 10; i++){
        sum += ntohs(*ptr);//将大端字节序转换为小端字节序
        ptr++;
    }
    // 把高16位和低16位相加
    while(sum >> 16){
        sum = (sum >> 16) + (sum & 0xffff);
    }
    //返回校验和    ~sum表示取反
    return (uint16_t)(~sum);
}

void print_binary(uint16_t value, int bits) {
    for (int i = bits - 1; i >= 0; --i) {
        printf("%d", (value >> i) & 1);
    }
    printf("\n");
}

void showIPPacket(struct ip_header* iphdr) {
    printf("===========开始解析IP层数据包========== \n");
    printf("版本号: %d\n", (iphdr->Ver_HLen >> 4));
    printf("首部长度: %d\n", (iphdr->Ver_HLen & 0x0F) * 4);
    printf("服务类型: %d\n", (int)iphdr->TOS);
    switch ((int)iphdr->TOS >> 5) {
    case 0:
        printf("优先级: Routine,数据包不需要特殊处理。\n");
        break;
    case 1:
        printf("优先级: Priority,数据包不需要特殊处理。\n");
        break;
    case 2:
        printf("优先级: Immediate,数据包需要立即处理。\n");
        break;
    case 3:
        printf("优先级: Flash,数据包需要快速处理。\n");
        break;
    case 4:
        printf("优先级: Flash Override,数据包需要立即处理，并覆盖其他数据包的处理。\n");
        break;
    case 5:
        printf("优先级: CRITIC/ECP,数据包是关键数据或网络控制数据，需要最高优先级处理。\n");
        break;
    case 6:
        printf("优先级: Internetwork Control,数据包是网络控制数据，需要高优先级处理。\n");
        break;
    case 7:
        printf("优先级: Network Control,数据包是网络控制数据，需要最高优先级处理。\n");
        break;
    }
    printf("总长度: %d\n", ntohs(iphdr->TotalLen));
    printf("标识: %d\n", ntohs(iphdr->ID));
    printf("标志: ");
    print_binary(ntohs(iphdr->Flag_Segment) >> 10, 6);
    printf("对应标志: URG、ACK、PSH、RST、SYN 和 FIN 六个标志位。\n");
    printf("片偏移: %d\n", (ntohs(iphdr->Flag_Segment) & 0x1FFF));
    printf("生存时间: %d\n", (int)iphdr->TTL);
    printf("协议编号: %d\n", (int)iphdr->Protocol);
    switch ((int)iphdr->Protocol) {
    case 1:
        printf("协议类型: ICMP\n");
        break;
    case 2:
        printf("协议类型: IGMP\n");
        break;
    case 6:
        printf("协议类型: TCP\n");
        break;
    case 17:
        printf("协议类型: UDP\n");
        break;
    case 58:
        printf("协议类型: ICMPv6\n");
        break;
    case 89:
        printf("协议类型: OSPF\n");
        break;
    case 132:
        printf("协议类型: SCTP\n");
        break;
    case 255:
        printf("协议类型: RAW\n");
        break;
    }
    printf("首部校验和: %d\n", ntohs(iphdr->Checksum));
    printf("源IP地址: %s\n", inet_ntoa(*(struct in_addr *)&iphdr->SrcIP));
    printf("目的IP地址: %s\n", inet_ntoa(*(struct in_addr *)&iphdr->DstIP));
    printf("===========完成IP层数据包解析======== \n\n");
}

void analysis_ip(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    // 参数解释
    //  user_data传递用户定义的数据到回调函数中，通常用不到
    //  pkInfo保存了此数据包的时间信息和长度信息
    //  packet是数据包的内容
    struct ip_header *ip_protocol;
    ip_protocol = (struct ip_header *)(packet + 14); // 获取IP头，14 是因为以太网帧头部通常是 14 字节
    showIPPacket(ip_protocol);
}

void showEtherPacket(struct ether_header* ethhdr) {
    uint16_t type = ntohs(ethhdr->Ethernet_Type);
    printf("===========开始解析以太网帧数据包======== \n");
    printf("目的MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            ethhdr->Ethernet_Dhost[0], ethhdr->Ethernet_Dhost[1], ethhdr->Ethernet_Dhost[2], 
            ethhdr->Ethernet_Dhost[3], ethhdr->Ethernet_Dhost[4], ethhdr->Ethernet_Dhost[5]);
    printf("源MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            ethhdr->Ethernet_Shost[0], ethhdr->Ethernet_Shost[1], ethhdr->Ethernet_Shost[2], 
            ethhdr->Ethernet_Shost[3], ethhdr->Ethernet_Shost[4], ethhdr->Ethernet_Shost[5]);
    printf("以太网类型：%04x\n", type);
    switch (type) {
    case 0x0800:
        printf("以太网类型: IP\n");
        break;
    case 0x0806:
        printf("以太网类型: ARP\n");
        break;
    case 0x8035:
        printf("以太网类型: RARP\n");
        break;
    case 0x86DD:
        printf("以太网类型: IPv6\n");
        break;
    default:
        printf("以太网类型: 其他\n");
        break;
    }
    printf("===========完成以太网帧数据包解析======== \n\n");
}

void analysis_ether(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ether_header *ethhdr;
    ethhdr = (struct ether_header *)packet; // 获取以太网帧头部
    showEtherPacket(ethhdr);
}
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 定义以太网和IP头的最小总长度
    const unsigned int MIN_PACKET_LEN = 14 + 20;
    printf("--------------捕获到一个数据包--------------\n");

    // 检查数据包长度
    if (pkthdr->len < MIN_PACKET_LEN)
    {
        fprintf(stderr, "Packet is too short (%d bytes), unable to parse\n", pkthdr->len);
        return;
    }
    analysis_ether(user_data, pkthdr, packet);
    analysis_ip(user_data, pkthdr, packet);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev;

    // 获取本地机器上所有网络设备的列表
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }
    if (alldevs == NULL) {
        printf("No devices found.\n");
        return 1;
    }
    dev = alldevs->name;  // 获取第一个网络设备的名称

    // 打开指定的网络设备并监听
    // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // if (handle == NULL) {
    //     printf("Error opening device: %s\n", errbuf);
    //     return 1;
    // }
    //这是使用wireshark的测试用例
    handle = pcap_open_offline("test.pcap", errbuf);
    if(handle == NULL){
        printf("Error opening file: %s\n", errbuf);
        return 1;
    }

    // 检查数据链路层是否为以太网
    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("Device does not provide Ethernet headers.\n");
        pcap_close(handle);
        return 1;
    }

    // 捕获数据包并调用指定的回调函数packet_handler进行处理。
    pcap_loop(handle, 0, packet_handler, NULL);

    // 关闭已打开的网络设备并释放资源
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}