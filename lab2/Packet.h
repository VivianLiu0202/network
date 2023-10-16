#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>

struct ether_header
{
    uint8_t Ethernet_Dhost[6]; // 目的地址
    uint8_t Ethernet_Shost[6]; // 源地址
    uint16_t Ethernet_Type;    // 以太网类型
};

struct ip_header // IP首部
{
    uint8_t Ver_HLen;      // 8位版本+首部长度
    uint8_t TOS;           // 8位服务类型
    uint16_t TotalLen;     // 16位总长度
    uint16_t ID;           // 16位标识
    uint16_t Flag_Segment; // 16位标志+片偏移
    uint8_t TTL;           // 8位生存时间
    uint8_t Protocol;      // 8位协议
    uint16_t Checksum;     // 16位首部校验和
    uint32_t SrcIP;        // 32位源IP地址
    uint32_t DstIP;        // 32位目的IP地址
};

void analysis_IP(u_char *user_data, const struct pcap_pkthdr *pkInfo, const u_char *packet);       // 抓包函数的回调函数handler IP包头分析
void analysis_Ethernet(u_char *user_data, const struct pcap_pkthdr *pkInfo, const u_char *packet); // 抓包函数的回调函数handler IP包头分析
void showDevice();                                                                                 // 显示设备
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
