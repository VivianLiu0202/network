#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "router.h"
#pragma comment(lib, "ws2_32.lib") // ����ws2_32.lib���ļ�������Ŀ��
#include <stdio.h>
#include <iostream>
using namespace std;

// �궨��
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10

// ���߳�
HANDLE hThread;
DWORD dwThreadId;

pcap_if_t *alldevs;
pcap_if_t *device;
pcap_t *ahandle; // open������
pcap_addr *a;	 // ������Ӧ�ĵ�ַ
char errbuf[PCAP_ERRBUF_SIZE];
char *pcap_src_if_string; //

char ip[10][20];   // ���������ж˿ڵ�IP��ַ
char mask[10][20]; // �����ϵ����С�������mask
BYTE selfmac[6];   // ����mac��ַ~

BYTE broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // �㲥MAC��ַ

int ARP_Table::num = 0;

int index = 0;

// ʶ��Ƚ�IP��ַ��MAC��ַ�����˱���
int compare(BYTE a[6], BYTE b[6])
{
	int index = 1;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			index = 0;
	}
	return index;
}

// ��ȡĿ��IP��MAC��ַ
void GetOtherMAC(DWORD dest_ip, BYTE mac[])
{
	memset(mac, 0, sizeof(mac));
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	ARP_Header ARPFrame;

	int flag;
	int ret = 1;

	ARPFrame.FrameHeader.ether_type = htons(0x0806);
	memset(ARPFrame.FrameHeader.ether_dhost, 0xff, 6);
	memset(ARPFrame.TargetHardwareAddress, 0x00, 6);
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.ether_shost[i] = ARPFrame.SenderHardwareAddress[i] = selfmac[i];
	// ��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	ARPFrame.HardwareType = htons(0x0001); // Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800); // Э������ΪIP
	ARPFrame.HardwareSize = 6;			   // Ӳ����ַ����Ϊ6
	ARPFrame.ProtocolSize = 4;			   // Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);	   // ����ΪARP����
	ARPFrame.SenderProtocolAddress = inet_addr(ip[0]);
	ARPFrame.TargetProtocolAddress = dest_ip;

	if (ahandle == nullptr)
		cout << "ERROR!: �����ӿڴ򿪴���T_T~"
			 << endl;
	else
	{
		if (pcap_sendpacket(ahandle, (u_char *)&ARPFrame, sizeof(ARP_Header)) != 0)
		{
			// ���ʹ�����
			cout << "ERROR: send ERROR!" << endl;
		}
		else
		{
			// ���ͳɹ�
			cout << "SUCCESS: �ɹ�����ARP���ݰ�!!!!QAQ" << endl;
			while ((flag = pcap_next_ex(ahandle, &pkt_header, &pkt_data) > 0))
			{
				if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) // arp ��̫֡���ϲ�Э������
					&& *(uint16_t *)(pkt_data + 20) == htons(2)	  // ��Ӧ arp��������
					&& *(uint32_t *)(pkt_data + 28) == ARPFrame.TargetProtocolAddress)
				{
					// ip��ȷ
					cout << "SUCCESS: Ŀ��MAC��ȡ�ɹ�!!!!QWQ" << endl;
					cout << "INFO: Ŀ��MACΪ: " << endl;
					for (int i = 0; i < 6; i++)
					{
						mac[i] = *(uint8_t *)(pkt_data + 22 + i);
						printf("%02x", mac[i]);
						if (i != 5)
							cout << ":";
					}
					cout << endl;
					break;
				}
			}
		}
	}
}

void RouteItem::PrintItem() // ��ӡ·�ɱ�
{
	in_addr addr;
	cout << "·�ɱ�����Ϊ��" << index << endl;

	addr.s_addr = Mask;
	char *p = inet_ntoa(addr);
	cout << "����Ϊ��" << p << endl;

	addr.s_addr = TargetNet;
	p = inet_ntoa(addr);
	cout << "Ŀ������Ϊ��" << p << endl;

	addr.s_addr = nextIp;
	p = inet_ntoa(addr);
	cout << p << endl;
	cout << "��һ��IPΪ��" << p << endl;
	cout << type << endl;
}

// ·�ɱ��ʼ�������ֱ�����ӵ�����
RouteTable::RouteTable()
{
	head = new RouteItem;
	tail = new RouteItem;
	head->next_item = tail;
	num = 0;
	for (int i = 0; i < 2; i++)
	{
		RouteItem *routeitem = new RouteItem;
		// ����������ip ��������а�λ�뼴Ϊ��������
		routeitem->TargetNet = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		routeitem->Mask = inet_addr(mask[i]);
		routeitem->type = 0;		   // 0��ʾֱ��Ͷ�ݵ����磬����ɾ��
		this->AddRouteItem(routeitem); // ��ӱ���
	}
}

// ���·�ɱ���
void RouteTable::AddRouteItem(RouteItem *routeitem)
{
	RouteItem *current;
	// �ҵ����ʵĵط�
	if (!routeitem->type) //  0 ֱ��Ͷ��
	{
		routeitem->next_item = head->next_item;
		head->next_item = routeitem;
		routeitem->type = 0;
	}
	// ���������������ɳ������ҵ����ʵ�λ��
	else
	{
		for (current = head->next_item; current != tail && current->next_item != tail; current = current->next_item) // head�����ݣ�tailû��
		{
			if (routeitem->Mask < current->Mask && routeitem->Mask >= current->next_item->Mask || current->next_item == tail)
				break;
		}
		// ���뵽����λ��
		routeitem->next_item = current->next_item;
		current->next_item = routeitem;
	}
	RouteItem *p = head->next_item;
	for (int i = 0; p != tail; p = p->next_item, i++)
	{
		p->index = i;
	}
	this->num++;
}

// ɾ��·�ɱ���
void RouteTable::RemoveRouteItem(int index)
{
	for (RouteItem *item = head; item->next_item != tail; item = item->next_item)
	{
		if (item->next_item->index == index)
		{
			// ֱ��Ͷ�ݵ�·�ɱ����ɾ��
			if (item->next_item->type == 0) // ֱ��Ͷ�ݵ�·�ɱ����ɾ��
			{
				cout << "����Ϊֱ��Ͷ�ݵ�·�ɱ������ɾ��" << endl;
				return;
			}
			else
			{
				item->next_item = item->next_item->next_item;
				return;
			}
		}
	}
	cout << "�ñ������" << endl;
}

// ��ӡ·�ɱ�
void RouteTable::printRouteTable()
{
	for (RouteItem *item = head->next_item; item != tail; item = item->next_item)
		item->PrintItem();
}

// ����·�ɱ��Ӧ����,��������һ����ip��ַ
DWORD RouteTable::SearchNext(DWORD ip)
{
	for (RouteItem *item = head->next_item; item != tail; item = item->next_item)
	{
		if ((item->Mask & ip) == item->TargetNet)
			return item->nextIp;
	}
	return -1;
}

// ���ARP����
void ARP_Table::addARPItem(DWORD ip, BYTE mac[6])
{
	cout << "INFO: ��ʼ���ARP����QQQ" << endl;
	arp_table[num].ip = ip;
	GetOtherMAC(ip, arp_table[num].mac);
	memcpy(mac, arp_table[num].mac, 6);
	num++; // �������++
	cout << "SUCCESS:���ARP����ɹ�QAQ" << endl;
	cout << "num: " << num << endl;
}

int ARP_Table::SearchARPItem(DWORD ip, BYTE mac[6])
{
	cout << "INFO: ����ARP����ing" << endl;
	memset(mac, 0, 6);
	cout << "num: " << num << endl;
	for (int i = 0; i < num; i++)
	{
		if (ip == arp_table[i].ip)
		{
			cout << "SUCCESS: �ҵ���Ӧ��MAC��ַQWWQ" << endl;
			memcpy(mac, arp_table[i].mac, 6);
			return 1;
		}
	}
	return 0;
}

// ��ȡ�������豸�б�������ip����ip������,��ȡIP��mask��������������
void find_alldevs()
{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1)
	{
		printf("%s", "error");
	}
	else
	{
		int i = 0;
		for (device = alldevs; device != NULL; device = device->next) // ��ȡ������ӿ��豸��ip��ַ��Ϣ
		{
			if (i == index)
			{
				int t = 0;
				for (a = device->addresses; a != nullptr; a = a->next)
				{
					if (((struct sockaddr_in *)a->addr)->sin_family == AF_INET && a->addr)
					{
						printf("%d ", i);
						printf("%s\t", device->name, device->description);
						printf("%s\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
						// �洢��ӦIP��ַ��MAC��ַ
						strcpy(ip[t], inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
						strcpy(mask[t++], inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
					}
				}
				ahandle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
			}
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}

// ��ȡ������MAC��ַ
void GetSelfMAC(DWORD ip) // ��ñ���IP��ַ�Լ���Ӧ��MAC��ַ
{
	memset(selfmac, 0, sizeof(selfmac));
	ARP_Header ARPFrame;
	// ��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.ether_dhost[i] = 0xff;

	ARPFrame.FrameHeader.ether_shost[0] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[1] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[2] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[3] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[4] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[5] = 0x0f;

	ARPFrame.FrameHeader.ether_type = htons(0x0806); // ֡����ΪARP

	ARPFrame.HardwareType = htons(0x0001); // Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800); // Э������ΪIP
	ARPFrame.HardwareSize = 6;			   // Ӳ����ַ����Ϊ6
	ARPFrame.ProtocolSize = 4;			   // Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);	   // ����ΪARP����

	ARPFrame.SenderHardwareAddress[0] = 0x0f;
	ARPFrame.SenderHardwareAddress[1] = 0x0f;
	ARPFrame.SenderHardwareAddress[2] = 0x0f;
	ARPFrame.SenderHardwareAddress[3] = 0x0f;
	ARPFrame.SenderHardwareAddress[4] = 0x0f;
	ARPFrame.SenderHardwareAddress[5] = 0x0f;

	ARPFrame.SenderProtocolAddress = inet_addr("122.122.122.122");
	for (int i = 0; i < 6; i++)
		ARPFrame.TargetHardwareAddress[i] = 0;

	ARPFrame.TargetProtocolAddress = ip;
	cout << "hhhhhhhhhhhhello��" << endl;

	if (ahandle == nullptr)
		printf("�����ӿڴ򿪴���\n");
	else
	{
		if (pcap_sendpacket(ahandle, (u_char *)&ARPFrame, sizeof(ARP_Header)) != 0)
		{
			printf("senderror\n");
		}
		else
		{
			cout << "�������ݰ��ɹ�" << endl;
			while (1)
			{
				struct pcap_pkthdr *pkt_header;
				const u_char *pkt_data;
				int ret = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (ret > 0)
				{
					if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) && *(uint16_t *)(pkt_data + 20) == htons(2) && *(uint32_t *)(pkt_data + 28) == ARPFrame.TargetProtocolAddress)
					{
						cout << "SUCCESS: �ɹ��������������MAC��ַqqq" << endl;
						cout << "INFO: MAC��: ";
						for (int i = 0; i < 6; i++)
						{
							selfmac[i] = *(uint8_t *)(pkt_data + 22 + i);
							printf("%02x", selfmac[i]);
							if (i != 5)
								cout << ":";
						}
						cout << endl;
						break;
					}
				}
			}
		}
	}
}

void printMac(BYTE MAC[]) // ��ӡmac
{
	cout << "SUCCESS: �ɹ���ӡMAC��ַ!!";
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}

// ���ݱ�ת��,�޸�Դmac��Ŀ��mac
void PacketResend(ICMP_t icmpdata, BYTE destinationMAC[])
{
	cout << "INFO: ����ת������!!" << endl;
	ICMP_t *icmp = (ICMP_t *)&icmpdata;
	Data_t *changed_icmp = (Data_t *)&icmpdata;
	memcpy(icmp->FrameHeader.ether_shost, icmp->FrameHeader.ether_dhost, 6); // ԴMACΪ����MAC
	memcpy(icmp->FrameHeader.ether_dhost, destinationMAC, 6);				 // Ŀ��MACΪ��һ��MAC
	icmp->IPHeader.TTL -= 1;
	cout << "INFO: TTL = " << icmp->IPHeader.TTL << endl;
	//  ���TTLС��0������
	if (icmp->IPHeader.TTL < 0)
		return;
	setChecksum(&(icmp->IPHeader));
	cout << "SUCCESS: ����У��ͳɹ�!" << endl;								  // ��������У���
	int ret = pcap_sendpacket(ahandle, (const u_char *)icmp, sizeof(ICMP_t)); // �������ݱ�
	if (ret == 0)
		cout << "INFO: ת��" << changed_icmp << endl;
}

DWORD WINAPI handlePacket(LPVOID lparam) // ���պʹ����̺߳���
{
	RouteTable routetable = *(RouteTable *)(LPVOID)lparam; // ��·�ɱ���
	while (1)
	{
		pcap_pkthdr *pkt_header;
		const u_char *pkt_data;
		// һֱ����packet
		while (1)
		{
			int ret = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (ret) // ���յ���Ϣ
				break;
		}
		Ethernet_Header *header = (Ethernet_Header *)pkt_data;
		// ���Ŀ��mac���Լ���mac
		if (compare(header->ether_dhost, selfmac))
		{
			// ��IP���ݰ�
			if (ntohs(header->ether_type) == 0x800)
			{
				Data_t *data = (Data_t *)pkt_data; // ֻ��ȡ�ײ�
				ICMP_t *icmp = (ICMP_t *)pkt_data; // ��ȡ�ײ�������
				DWORD ip1_ = data->IPHeader.DstIP;
				DWORD ip2 = routetable.SearchNext(ip1_); // �����Ƿ��ж�Ӧ����
				if (ip2 == -1)							 // ���û����ֱ�Ӷ�����ֱ�ӵݽ����ϲ�
					continue;
				if (Checksum(&(icmp->IPHeader))) // ���У��Ͳ���ȷ����ֱ�Ӷ��������д���
				{
					cout << "SUCCESS: У�����ȷ!!!" << endl;
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1])) // ��Ŀ��IP��Ԥ�������IP�ȶԣ���Ҫ·��
					{
						cout << "INFO: ��Ҫ·��" << endl;
						int t1 = compare(data->FrameHeader.ether_dhost, broadcast);
						int t2 = compare(data->FrameHeader.ether_shost, broadcast);
						if (!t1 && !t2)
						{
							cout << "INFO: t1,t2�����ǹ㲥��ַ" << endl;
							// ICMP���İ���IP���ݰ���ͷ����������
							ICMP_t *temp_ = (ICMP_t *)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							if (ip2 == 0)
							{
								//  ���ARP����û���������ݣ�����Ҫ��ȡARP
								if (!ARP_Table::SearchARPItem(ip1_, mac))
									ARP_Table::addARPItem(ip1_, mac);
								PacketResend(temp, mac);
								cout << "SUCCESS: ���ݰ�ת���ɹ�!!" << endl;
							}
							if (ip2 != -1) // ��ֱ��Ͷ�ݣ�������һ��IP��MAC
							{
								if (!ARP_Table::SearchARPItem(ip2, mac))
									ARP_Table::addARPItem(ip2, mac);
								PacketResend(temp, mac);
								cout << "SUCCESS: ���ݰ�ת���ɹ�!!" << endl;
							}
						}
					}
				}
			}
		}
	}
}

int main()
{
	scanf("%d", &index);
	// #define PCAP_SRC_IF_STRING "rpcap://"
	// ����ָ��Զ�̲���Э�飨RPCAP���ĵ�ַ��ʽ������һ�ֳ������������ݰ�������Э�顣
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);

	find_alldevs(); // ��ȡ����ip

	for (int i = 0; i < 2; i++) // �����ʱ�洢��IP��ַ��MAC��ַ
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	GetSelfMAC(inet_addr(ip[0]));
	printMac(selfmac);
	BYTE mac[6];
	int op;
	RouteTable routetable;
	hThread = CreateThread(NULL, 0, handlePacket, LPVOID(&routetable), 0, NULL);

	RouteItem a;
	while (1)
	{
		printf("��ѡ��������:\n1.���·�ɱ���\n2.ɾ��·�ɱ���\n3.��ӡ·�ɱ�\n");
		printf("������������:");
		scanf("%d", &op);
		if (op == 1)
		{
			RouteItem a;
			char t[30];
			printf("�������룺");
			scanf("%s", &t);
			a.Mask = inet_addr(t);
			printf("����Ŀ�����磺");
			scanf("%s", &t);
			a.TargetNet = inet_addr(t);
			printf("������һ����ַ��");
			scanf("%s", &t);
			a.nextIp = inet_addr(t);
			a.type = 1;
			routetable.AddRouteItem(&a);
		}
		else if (op == 2)
		{
			printf("����ɾ�������ţ�");
			int index;
			scanf("%d", &index);
			routetable.RemoveRouteItem(index);
		}
		else if (op == 3)
		{
			routetable.printRouteTable();
		}
		else
		{
			printf("��Ч������������ѡ��QWQQQQQ\n");
		}
	}
	RouteTable table;
	table.printRouteTable();
	return 0;
	system("pause");
}
