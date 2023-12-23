#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "router.h"
#pragma comment(lib, "ws2_32.lib") // 链接ws2_32.lib库文件到此项目中
#include <stdio.h>
#include <iostream>
using namespace std;

// 宏定义
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10

// 多线程
HANDLE hThread;
DWORD dwThreadId;

pcap_if_t *alldevs;
pcap_if_t *device;
pcap_t *ahandle; // open的网卡
pcap_addr *a;	 // 网卡对应的地址
char errbuf[PCAP_ERRBUF_SIZE];
char *pcap_src_if_string; //

char ip[10][20];   // 本机上所有端口的IP地址
char mask[10][20]; // 本机上的所有。。。的mask
BYTE selfmac[6];   // 本机mac地址~

BYTE broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // 广播MAC地址

int ARP_Table::num = 0;

int index = 0;

// 识别比较IP地址与MAC地址，过滤报文
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

// 获取目的IP的MAC地址
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
	// 将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	ARPFrame.HardwareType = htons(0x0001); // 硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800); // 协议类型为IP
	ARPFrame.HardwareSize = 6;			   // 硬件地址长度为6
	ARPFrame.ProtocolSize = 4;			   // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);	   // 操作为ARP请求
	ARPFrame.SenderProtocolAddress = inet_addr(ip[0]);
	ARPFrame.TargetProtocolAddress = dest_ip;

	if (ahandle == nullptr)
		cout << "ERROR!: 网卡接口打开错误T_T~"
			 << endl;
	else
	{
		if (pcap_sendpacket(ahandle, (u_char *)&ARPFrame, sizeof(ARP_Header)) != 0)
		{
			// 发送错误处理
			cout << "ERROR: send ERROR!" << endl;
		}
		else
		{
			// 发送成功
			cout << "SUCCESS: 成功发送ARP数据包!!!!QAQ" << endl;
			while ((flag = pcap_next_ex(ahandle, &pkt_header, &pkt_data) > 0))
			{
				if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) // arp 以太帧的上层协议类型
					&& *(uint16_t *)(pkt_data + 20) == htons(2)	  // 响应 arp操作类型
					&& *(uint32_t *)(pkt_data + 28) == ARPFrame.TargetProtocolAddress)
				{
					// ip正确
					cout << "SUCCESS: 目标MAC获取成功!!!!QWQ" << endl;
					cout << "INFO: 目标MAC为: " << endl;
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

void RouteItem::PrintItem() // 打印路由表
{
	in_addr addr;
	cout << "路由表索引为：" << index << endl;

	addr.s_addr = Mask;
	char *p = inet_ntoa(addr);
	cout << "掩码为：" << p << endl;

	addr.s_addr = TargetNet;
	p = inet_ntoa(addr);
	cout << "目的网络为：" << p << endl;

	addr.s_addr = nextIp;
	p = inet_ntoa(addr);
	cout << p << endl;
	cout << "下一跳IP为：" << p << endl;
	cout << type << endl;
}

// 路由表初始化，添加直接连接的网络
RouteTable::RouteTable()
{
	head = new RouteItem;
	tail = new RouteItem;
	head->next_item = tail;
	num = 0;
	for (int i = 0; i < 2; i++)
	{
		RouteItem *routeitem = new RouteItem;
		// 本机网卡的ip 和掩码进行按位与即为所在网络
		routeitem->TargetNet = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		routeitem->Mask = inet_addr(mask[i]);
		routeitem->type = 0;		   // 0表示直接投递的网络，不可删除
		this->AddRouteItem(routeitem); // 添加表项
	}
}

// 添加路由表项
void RouteTable::AddRouteItem(RouteItem *routeitem)
{
	RouteItem *current;
	// 找到合适的地方
	if (!routeitem->type) //  0 直接投递
	{
		routeitem->next_item = head->next_item;
		head->next_item = routeitem;
		routeitem->type = 0;
	}
	// 其它，按照掩码由长至短找到合适的位置
	else
	{
		for (current = head->next_item; current != tail && current->next_item != tail; current = current->next_item) // head有内容，tail没有
		{
			if (routeitem->Mask < current->Mask && routeitem->Mask >= current->next_item->Mask || current->next_item == tail)
				break;
		}
		// 插入到合适位置
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

// 删除路由表项
void RouteTable::RemoveRouteItem(int index)
{
	for (RouteItem *item = head; item->next_item != tail; item = item->next_item)
	{
		if (item->next_item->index == index)
		{
			// 直接投递的路由表项不可删除
			if (item->next_item->type == 0) // 直接投递的路由表项不可删除
			{
				cout << "该项为直接投递的路由表项，不可删除" << endl;
				return;
			}
			else
			{
				item->next_item = item->next_item->next_item;
				return;
			}
		}
	}
	cout << "该表项不存在" << endl;
}

// 打印路由表
void RouteTable::printRouteTable()
{
	for (RouteItem *item = head->next_item; item != tail; item = item->next_item)
		item->PrintItem();
}

// 查找路由表对应表项,并给出下一跳的ip地址
DWORD RouteTable::SearchNext(DWORD ip)
{
	for (RouteItem *item = head->next_item; item != tail; item = item->next_item)
	{
		if ((item->Mask & ip) == item->TargetNet)
			return item->nextIp;
	}
	return -1;
}

// 添加ARP表项
void ARP_Table::addARPItem(DWORD ip, BYTE mac[6])
{
	cout << "INFO: 开始添加ARP表项QQQ" << endl;
	arp_table[num].ip = ip;
	GetOtherMAC(ip, arp_table[num].mac);
	memcpy(mac, arp_table[num].mac, 6);
	num++; // 表项个数++
	cout << "SUCCESS:添加ARP表项成功QAQ" << endl;
	cout << "num: " << num << endl;
}

int ARP_Table::SearchARPItem(DWORD ip, BYTE mac[6])
{
	cout << "INFO: 查找ARP表项ing" << endl;
	memset(mac, 0, 6);
	cout << "num: " << num << endl;
	for (int i = 0; i < num; i++)
	{
		if (ip == arp_table[i].ip)
		{
			cout << "SUCCESS: 找到对应的MAC地址QWWQ" << endl;
			memcpy(mac, arp_table[i].mac, 6);
			return 1;
		}
	}
	return 0;
}

// 获取本机的设备列表，将两个ip存入ip数组中,获取IP、mask，计算所在网段
void find_alldevs()
{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1)
	{
		printf("%s", "error");
	}
	else
	{
		int i = 0;
		for (device = alldevs; device != NULL; device = device->next) // 获取该网络接口设备的ip地址信息
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
						printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
						// 存储对应IP地址与MAC地址
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

// 获取本机的MAC地址
void GetSelfMAC(DWORD ip) // 获得本地IP地址以及对应的MAC地址
{
	memset(selfmac, 0, sizeof(selfmac));
	ARP_Header ARPFrame;
	// 将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.ether_dhost[i] = 0xff;

	ARPFrame.FrameHeader.ether_shost[0] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[1] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[2] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[3] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[4] = 0x0f;
	ARPFrame.FrameHeader.ether_shost[5] = 0x0f;

	ARPFrame.FrameHeader.ether_type = htons(0x0806); // 帧类型为ARP

	ARPFrame.HardwareType = htons(0x0001); // 硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800); // 协议类型为IP
	ARPFrame.HardwareSize = 6;			   // 硬件地址长度为6
	ARPFrame.ProtocolSize = 4;			   // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);	   // 操作为ARP请求

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
	cout << "hhhhhhhhhhhhello！" << endl;

	if (ahandle == nullptr)
		printf("网卡接口打开错误\n");
	else
	{
		if (pcap_sendpacket(ahandle, (u_char *)&ARPFrame, sizeof(ARP_Header)) != 0)
		{
			printf("senderror\n");
		}
		else
		{
			cout << "发送数据包成功" << endl;
			while (1)
			{
				struct pcap_pkthdr *pkt_header;
				const u_char *pkt_data;
				int ret = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (ret > 0)
				{
					if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) && *(uint16_t *)(pkt_data + 20) == htons(2) && *(uint32_t *)(pkt_data + 28) == ARPFrame.TargetProtocolAddress)
					{
						cout << "SUCCESS: 成功获得自身主机的MAC地址qqq" << endl;
						cout << "INFO: MAC是: ";
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

void printMac(BYTE MAC[]) // 打印mac
{
	cout << "SUCCESS: 成功打印MAC地址!!";
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}

// 数据报转发,修改源mac和目的mac
void PacketResend(ICMP_t icmpdata, BYTE destinationMAC[])
{
	cout << "INFO: 进入转发函数!!" << endl;
	ICMP_t *icmp = (ICMP_t *)&icmpdata;
	Data_t *changed_icmp = (Data_t *)&icmpdata;
	memcpy(icmp->FrameHeader.ether_shost, icmp->FrameHeader.ether_dhost, 6); // 源MAC为本机MAC
	memcpy(icmp->FrameHeader.ether_dhost, destinationMAC, 6);				 // 目的MAC为下一跳MAC
	icmp->IPHeader.TTL -= 1;
	cout << "INFO: TTL = " << icmp->IPHeader.TTL << endl;
	//  如果TTL小于0，则丢弃
	if (icmp->IPHeader.TTL < 0)
		return;
	setChecksum(&(icmp->IPHeader));
	cout << "SUCCESS: 设置校验和成功!" << endl;								  // 重新设置校验和
	int ret = pcap_sendpacket(ahandle, (const u_char *)icmp, sizeof(ICMP_t)); // 发送数据报
	if (ret == 0)
		cout << "INFO: 转发" << changed_icmp << endl;
}

DWORD WINAPI handlePacket(LPVOID lparam) // 接收和处理线程函数
{
	RouteTable routetable = *(RouteTable *)(LPVOID)lparam; // 将路由表传入
	while (1)
	{
		pcap_pkthdr *pkt_header;
		const u_char *pkt_data;
		// 一直接受packet
		while (1)
		{
			int ret = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (ret) // 接收到消息
				break;
		}
		Ethernet_Header *header = (Ethernet_Header *)pkt_data;
		// 如果目的mac是自己的mac
		if (compare(header->ether_dhost, selfmac))
		{
			// 是IP数据包
			if (ntohs(header->ether_type) == 0x800)
			{
				Data_t *data = (Data_t *)pkt_data; // 只提取首部
				ICMP_t *icmp = (ICMP_t *)pkt_data; // 提取首部和数据
				DWORD ip1_ = data->IPHeader.DstIP;
				DWORD ip2 = routetable.SearchNext(ip1_); // 查找是否有对应表项
				if (ip2 == -1)							 // 如果没有则直接丢弃或直接递交至上层
					continue;
				if (Checksum(&(icmp->IPHeader))) // 如果校验和不正确，则直接丢弃不进行处理
				{
					cout << "SUCCESS: 校验和正确!!!" << endl;
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1])) // 将目的IP与预设的两个IP比对，需要路由
					{
						cout << "INFO: 需要路由" << endl;
						int t1 = compare(data->FrameHeader.ether_dhost, broadcast);
						int t2 = compare(data->FrameHeader.ether_shost, broadcast);
						if (!t1 && !t2)
						{
							cout << "INFO: t1,t2都不是广播地址" << endl;
							// ICMP报文包含IP数据包报头和其它内容
							ICMP_t *temp_ = (ICMP_t *)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							if (ip2 == 0)
							{
								//  如果ARP表中没有所需内容，则需要获取ARP
								if (!ARP_Table::SearchARPItem(ip1_, mac))
									ARP_Table::addARPItem(ip1_, mac);
								PacketResend(temp, mac);
								cout << "SUCCESS: 数据包转发成功!!" << endl;
							}
							if (ip2 != -1) // 非直接投递，查找下一条IP的MAC
							{
								if (!ARP_Table::SearchARPItem(ip2, mac))
									ARP_Table::addARPItem(ip2, mac);
								PacketResend(temp, mac);
								cout << "SUCCESS: 数据包转发成功!!" << endl;
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
	// 用于指定远程捕获协议（RPCAP）的地址格式，这是一种常用于网络数据包捕获库的协议。
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);

	find_alldevs(); // 获取本机ip

	for (int i = 0; i < 2; i++) // 输出此时存储的IP地址与MAC地址
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
		printf("可选操作如下:\n1.添加路由表项\n2.删除路由表项\n3.打印路由表\n");
		printf("请输入操作编号:");
		scanf("%d", &op);
		if (op == 1)
		{
			RouteItem a;
			char t[30];
			printf("输入掩码：");
			scanf("%s", &t);
			a.Mask = inet_addr(t);
			printf("输入目的网络：");
			scanf("%s", &t);
			a.TargetNet = inet_addr(t);
			printf("输入下一跳地址：");
			scanf("%s", &t);
			a.nextIp = inet_addr(t);
			a.type = 1;
			routetable.AddRouteItem(&a);
		}
		else if (op == 2)
		{
			printf("输入删除表项编号：");
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
			printf("无效操作，请重新选择QWQQQQQ\n");
		}
	}
	RouteTable table;
	table.printRouteTable();
	return 0;
	system("pause");
}
