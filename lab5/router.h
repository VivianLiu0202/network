#pragma once
#include "pcap.h"
#pragma pack(1) // ��1byte��ʽ����

// �����ײ�
typedef struct Ethernet_Header
{						 // ֡�ײ�
	BYTE ether_dhost[6]; // Ŀ�ĵ�ַ
	BYTE ether_shost[6]; // Դ��ַ
	WORD ether_type;	 // ֡����
} Ethernet_Header;

// ARP���ĸ�ʽ
typedef struct ARP_Header
{								   // IP�ײ�
	Ethernet_Header FrameHeader;   // ֡�ײ�
	WORD HardwareType;			   // Ӳ������
	WORD ProtocolType;			   // Э������
	BYTE HardwareSize;			   // Ӳ����ַ����
	BYTE ProtocolSize;			   // Э���ַ
	WORD Operation;				   // ����
	BYTE SenderHardwareAddress[6]; // ���ͷ�MAC
	DWORD SenderProtocolAddress;   // ���ͷ�IP
	BYTE TargetHardwareAddress[6]; // ���շ�MAC
	DWORD TargetProtocolAddress;   // ���շ�IP
} ARP_Header;

// IP�����ײ�
typedef struct IP_Header
{
	BYTE Ver_HLen;	   // �汾+�ײ�����
	BYTE TOS;		   // ��������
	WORD TotalLen;	   // �ܳ���
	WORD ID;		   // ��ʶ
	WORD Flag_Segment; // ��־+Ƭƫ��
	BYTE TTL;		   // ��������
	BYTE Protocol;	   // �ϲ�Э������
	WORD Checksum;	   // У���
	ULONG SrcIP;	   // ԴIP
	ULONG DstIP;	   // Ŀ��IP
} IP_Header;

typedef struct Data_t
{								 // ����֡�ײ���IP�ײ������ݰ�
	Ethernet_Header FrameHeader; // ֡�ײ�
	IP_Header IPHeader;			 // IP�ײ�
} Data_t;

// ICMP�����ײ�
typedef struct ICMP_t
{								 // ����֡�ײ���IP�ײ������ݰ�
	Ethernet_Header FrameHeader; // ֡�ײ�
	IP_Header IPHeader;			 // IP�ײ�
	// BYTE Type;
	// BYTE Code;
	// WORD Checksum;
	// WORD Identifier;
	// WORD SequenceNumber;
	char buf[0x80];
} ICMP_t;

// ·�ɱ����
class RouteItem
{
public:
	DWORD Mask;		 // ����
	DWORD TargetNet; // Ŀ������
	DWORD nextIp;	 // ��һ����IP
	BYTE nextMAC[6]; // ��һ����MAC
	int index;		 // ����
	int type;		 // 0Ϊֱ�����ӣ�1Ϊ�û���ӣ�0����ɾ��
	RouteItem *next_item;
	RouteItem()
	{
		memset(this, 0, sizeof(*this));
	}
	void PrintItem(); // ��ӡ����
};

// ʹ������
class RouteTable
{
public:
	RouteItem *head, *tail; // ����ͷβ
	int num;				// ת����������
	RouteTable();			// ���캯��
	// ·�ɱ����ӣ�ֱ��Ͷ������ǰ��ǰ׺������ǰ��
	void AddRouteItem(RouteItem *a);
	// ɾ����type=0����ɾ��
	void RemoveRouteItem(int index);
	// ·�ɱ�Ĵ�ӡ
	void printRouteTable();
	// ���ң��ǰ׺,������һ����ip
	DWORD SearchNext(DWORD ip);
};

#pragma pack() // �ָ�4bytes����

class ARP_Table
{
public:
	DWORD ip;										 // IP��ַ
	BYTE mac[6];									 // MAC��ַ
	static int num;									 // ��������
	static void addARPItem(DWORD ip, BYTE mac[6]);	 // �������
	static int SearchARPItem(DWORD ip, BYTE mac[6]); // ���ұ����������
} arp_table[50];

// ===����===
void setChecksum(IP_Header *response)
{
	response->Checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // ÿ16λΪһ��
	int size = sizeof(IP_Header);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16λ���
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// ȡ��
	response->Checksum = (uint16_t)~checkSum;
}

bool Checksum(IP_Header *response)
{
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // ÿ16λΪһ��
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