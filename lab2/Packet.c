#include <stdio.h>
#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 检查数据包是否太短
    if (pkthdr->caplen < 14) {
        printf("Packet too short to extract MAC addresses and type/length field.\n");
        return;
    }

    // 提取源MAC地址、目的MAC地址和类型/长度字段
    const u_char *mac_src = packet + 6;
    const u_char *mac_dest = packet;
    u_short *type_length = (u_short *)(packet + 12);

    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
    printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_dest[0], mac_dest[1], mac_dest[2], mac_dest[3], mac_dest[4], mac_dest[5]);
    printf("Type/Length: %04x\n", ntohs(*type_length));
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
    dev = alldevs->name;  // Use the first device

    // 打开指定的网络设备并监听
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }
    //这是使用wireshark的测试用例
    // handle = pcap_open_offline("test.pcap", errbuf);
    // if(handle == NULL){
    //     printf("Error opening file: %s\n", errbuf);
    //     return 1;
    // }

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