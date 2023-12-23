#pragma once
#include "pcap.h"
#pragma pack(1) // 以1byte方式对齐

// 报文首部
typedef struct Ethernet_Header
{						 // 帧首部
	BYTE ether_dhost[6]; // 目的地址
	BYTE ether_shost[6]; // 源地址
	WORD ether_type;	 // 帧类型
} Ethernet_Header;

// ARP报文格式
typedef struct ARP_Header
{								   // IP首部
	Ethernet_Header FrameHeader;   // 帧首部
	WORD HardwareType;			   // 硬件类型
	WORD ProtocolType;			   // 协议类型
	BYTE HardwareSize;			   // 硬件地址长度
	BYTE ProtocolSize;			   // 协议地址
	WORD Operation;				   // 操作
	BYTE SenderHardwareAddress[6]; // 发送方MAC
	DWORD SenderProtocolAddress;   // 发送方IP
	BYTE TargetHardwareAddress[6]; // 接收方MAC
	DWORD TargetProtocolAddress;   // 接收方IP
} ARP_Header;

// IP报文首部
typedef struct IP_Header
{
	BYTE Ver_HLen;	   // 版本+首部长度
	BYTE TOS;		   // 服务类型
	WORD TotalLen;	   // 总长度
	WORD ID;		   // 标识
	WORD Flag_Segment; // 标志+片偏移
	BYTE TTL;		   // 生命周期
	BYTE Protocol;	   // 上层协议类型
	WORD Checksum;	   // 校验和
	ULONG SrcIP;	   // 源IP
	ULONG DstIP;	   // 目的IP
} IP_Header;

typedef struct Data_t
{								 // 包含帧首部和IP首部的数据包
	Ethernet_Header FrameHeader; // 帧首部
	IP_Header IPHeader;			 // IP首部
} Data_t;

// ICMP报文首部
typedef struct ICMP_t
{								 // 包含帧首部和IP首部的数据包
	Ethernet_Header FrameHeader; // 帧首部
	IP_Header IPHeader;			 // IP首部
	// BYTE Type;
	// BYTE Code;
	// WORD Checksum;
	// WORD Identifier;
	// WORD SequenceNumber;
	char buf[0x80];
} ICMP_t;

// 路由表表项
class RouteItem
{
public:
	DWORD Mask;		 // 掩码
	DWORD TargetNet; // 目的网络
	DWORD nextIp;	 // 下一跳的IP
	BYTE nextMAC[6]; // 下一跳的MAC
	int index;		 // 索引
	int type;		 // 0为直接连接，1为用户添加，0不可删除
	RouteItem *next_item;
	RouteItem()
	{
		memset(this, 0, sizeof(*this));
	}
	void PrintItem(); // 打印表项
};

// 使用链表
class RouteTable
{
public:
	RouteItem *head, *tail; // 链表头尾
	int num;				// 转发表项数量
	RouteTable();			// 构造函数
	// 路由表的添加，直接投递在最前，前缀长的在前面
	void AddRouteItem(RouteItem *a);
	// 删除，type=0不能删除
	void RemoveRouteItem(int index);
	// 路由表的打印
	void printRouteTable();
	// 查找，最长前缀,返回下一跳的ip
	DWORD SearchNext(DWORD ip);
};

#pragma pack() // 恢复4bytes对齐

class ARP_Table
{
public:
	DWORD ip;										 // IP地址
	BYTE mac[6];									 // MAC地址
	static int num;									 // 表项数量
	static void addARPItem(DWORD ip, BYTE mac[6]);	 // 插入表项
	static int SearchARPItem(DWORD ip, BYTE mac[6]); // 查找表项，返回索引
} arp_table[50];

// ===新增===
void setChecksum(IP_Header *response)
{
	response->Checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // 每16位为一组
	int size = sizeof(IP_Header);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16位相加
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// 取反
	response->Checksum = (uint16_t)~checkSum;
}

bool Checksum(IP_Header *response)
{
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // 每16位为一组
	bool checkOut = true;
	for (int i = 0; i < sizeof(IP_Header) / 2; i++)
	{
		checkSum += sec[i];
		while (checkSum >= 0x10000)
		{
			int c = checkSum >> 16;
			checkSum -= 0x10000;
			checkSum += c;
		}
	}
	if (sizeof(IP_Header) % 2 != 0)
	{
		checkSum += *(uint8_t *)(sec + (sizeof(IP_Header) - 1));
		while (checkSum >= 0x10000)
		{
			int c = checkSum >> 16;
			checkSum -= 0x10000;
			checkSum += c;
		}
	}
	checkOut = (checkSum == 0xffff) ? true : false;
	return checkOut;
}