<h1><center>Npcap & LibPcap</center></h1>

# 支持平台

### Npcap

- 主要为**Windows平台**设计，
- 基于 **WinPcap**基础上开发，与现代Windows版本更加兼容，支持所有的Windows架构（x86，x86_64，ARM）。
- Npcap 支持 Windows 7 到 Windows 11

下载地址：https://npcap.com/



### Libpcap

- 是一个跨平台的数据包捕获库；
- 支持多个操作系统，包括macOS、Linux，BSD等；
- 在Windows上的版本为`WinPcap`。

下载地址：https://www.tcpdump.org/



### Npcap与Winpcap的详细对比

Winpcap是Libpcap在Windows上的版本，Npcap相比之下多了部分功能

| Info                                | Npcap                                    | Winpcap       |
| ----------------------------------- | ---------------------------------------- | ------------- |
| 积极维护支持                        | Yes                                      | No            |
| 最后发布日期                        | 2023.7.20                                | 2013.3.8      |
| libpcap版本                         | 1.10.4（2023）                           | 1.0.0（2008） |
| License                             | Free for personal use                    | BSD-style     |
| 支持的商业/可再发行版本             | Yes：[Npcap OEM](https://npcap.com/oem/) | No            |
| **安全**                            | **Npcap**                                | **Winpcap**   |
| EV SHA-256 代码签名                 | Yes                                      | No            |
| 限制管理员的访问权限（可选）        | Yes                                      | No            |
| **基本特点**                        | **Npcap**                                | **Winpcap**   |
| 使用跨平台Libpcap API进行数据包捕获 | Yes                                      | Yes           |
| 链路层数据包注入                    | Yes                                      | Yes           |
| 可用源代码                          | Yes                                      | Yes           |
| **高级功能**                        | **Npcap**                                | **Winpcap**   |
| Capture raw 802.11 frames           | Yes                                      | Yes           |
| Capture Loopback traffic            | Yes                                      | No            |
| Inject Loopback traffic             | Yes                                      | No            |



# 功能性能

### Npcap

- **环回数据包捕获和注入**：Npcap 利用 Windows 过滤平台 (WFP)来嗅探同一计算机上的环回数据包。安装后，它提供一个名为 `NPF_Loopback` 的接口，描述为“Adapter for Loopback capture”。Wireshark 用户可以使用此适配器捕获所有环回流量。此外，数据包注入也支持 `pcap_inject()` 函数。
- **支持所有当前 Windows 版本（使用NDIS 6）**：Npcap 支持所有 Microsoft 仍在支持的 Windows 和 Windows Server 版本。它为每个主要平台发布驱动程序，确保在最新的 Win10 上使用最新技术，同时也支持旧系统。Npcap 在 Windows 7 及以上版本使用 [NDIS 6 轻量级筛选器 (LWF)](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) API，这比 WinPcap 的 NDIS 5 API 更快。该驱动程序已签名并获得 Microsoft 的会签，满足 Windows 10 的驱动程序签名要求。如果 Microsoft 移除 NDIS 5 或更改驱动程序签名政策，WinPcap 将不再工作。 
- **Libpcap API**：Npcap 使用 [Libpcap 库](https://www.tcpdump.org/)，支持 Windows 上的数据包捕获 API，同时包含最新的 Libpcap 版本及其改进。
- **支持“只允许管理员 Administrator”访问 Npcap**：Npcap 可设置为仅管理员访问。如果非管理员用户尝试通过[Nmap](https://nmap.org/)或 [Wireshark](https://www.wireshark.org/)等软件使用Npcap ，则用户必须通过[用户帐户控制 (UAC)](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7)对话框才能使用驱动程序。这在概念上类似于 UNIX，通常需要 root 访问权限来捕获数据包。同时Npcap启用了 Windows 的 ASLR、DEP 安全功能，并签名其组件。
- **WinPcap 兼容性**：软件编写为 WinPcap 兼容，但使用 Npcap SDK 重新编译可获得更多优势。虽然有一定的二进制兼容性，但建议进行[细微的更改](https://npcap.com/guide/npcap-devguide.html#npcap-devguide-updating)以优先使用 Npcap。Npcap 可替代或与 WinPcap 共存。
- **原始（监控模式）802.11 无线捕获**：Npcap 支持原始 802.11 无线捕获，包括 radiotap 标头，且 Wireshark 支持此功能。更多信息[在此](https://npcap.com/guide/npcap-devguide.html#npcap-feature-dot11)。



### Libpcap

- **跨平台支持**：Libpcap 提供了一个在多种Unix-like操作系统上进行原始数据包捕获的功能强大的用户级库。它在 Linux、macOS 以及其他多种 Unix 类型的系统上都可以运行，而不仅仅是限于某个特定的平台或架构，为开发者提供了广泛的开发和部署选择。
- **高效的数据包过滤**：Libpcap 拥有一个高效的数据包过滤系统，它能够在内核级别对数据包进行过滤，极大地减小了需要在用户空间处理的数据包的数量。开发者可以使用 BPF（Berkeley Packet Filter）语法定义数据包过滤规则，以便只捕获对分析和处理特定问题相关的数据包。
- **数据包捕获机制**：Libpcap 提供了多种数据包捕获的机制，例如 `pcap_loop()` 和 `pcap_dispatch()`，它们分别提供了基于数据包数量和超时的数据包捕获。此外，还有 `pcap_next()` 和 `pcap_next_ex()` 函数，这些函数提供了更简单的基于单个数据包的捕获方法。
- **易于使用的 API**：Libpcap 提供了一套简单且功能强大的 API，开发者可以使用这些 API 快速地构建自己的网络监控或分析工具。Libpcap API 允许开发者执行如打开网络接口、编译和应用过滤器、捕获数据包等基本操作。
- **底层数据包处理**：Libpcap 处理了与底层网络硬件和操作系统交互所需的所有细节，如读取数据包、处理数据包等，使开发者能够专注于处理捕获的数据包，而无需担心底层的具体实现细节。
- **开源与社区支持**：Libpcap 是开源的，并且有一个活跃的开发和用户社区。因此，它能够支持最新的网络技术和协议，也能够在遇到问题时得到社区的帮助和支持。
- **扩展性和兼容性**：Libpcap 支持通过各种语言的绑定和包装器在多种编程语言中使用，如 Python、Perl、Ruby 等。这为在多种场景和平台下开发网络工具提供了极大的便利和灵活性。同时，由于 Libpcap 的广泛使用，它在网络工具开发领域形成了一种事实上的标准，许多工具和库为其提供了支持或集成。



libpcap主要由两部分**组成**：网络分接头(Network Tap)和数据过滤器(Packet Filter)。网络分接头从网络设备驱动程序中收集数据拷贝，过滤器决定是否接收该数据包。Libpcap利用BSD Packet Filter(BPF)算法对网卡接收到的链路层数据包进行过滤。BPF算法的基本思想是在有BPF监听的网络中，网卡驱动将接收到的数据包复制一份交给BPF过滤器，过滤器根据用户定义的规则决定是否接收此数据包以及需要拷贝该数据包的那些内容，然后将过滤后的数据给与过滤器相关联的上层应用程序。

libpcap的**包捕获机制**就是在数据链路层加一个旁路处理。当一个数据包到达网络接口时，libpcap首先利用已经创建的Socket从链路层驱动程序中获得该数据包的拷贝，再通过Tap函数将数据包发给BPF过滤器。BPF过滤器根据用户已经定义好的过滤规则对数据包进行逐一匹配，匹配成功则放入内核缓冲区，并传递给用户缓冲区，匹配失败则直接丢弃。如果没有设置过滤规则，所有数据包都将放入内核缓冲区，并传递给用户层缓冲区。




# 抓包框架

### Npcap

**设备选择**

- `pcap_findalldevs_ex()`: 获取所有网络设备的列表，包括由 Npcap 驱动安装的适配器。

  **注意**: 这是 Npcap 的特有功能，支持列出远程机器上的设备，用于远程数据包捕获。

**打开网络设备**

- `pcap_open()`: 用于打开指定的网络设备以进行数据包捕获。它接受设备名称、捕获数据包的最大字节数、混杂模式标志、读取超时以及错误缓冲区作为参数。

  **注意**: 这也是 Npcap 的特有功能，允许打开远程或本地设备

**设置过滤器**

- `pcap_compile()`: 将过滤表达式编译为过滤程序。
- `pcap_setfilter()`: 将编译后的过滤程序设置到 pcap 句柄。

**数据包捕获**

- `pcap_loop()` 或 `pcap_dispatch()`: 捕获数据包并调用指定的回调函数进行处理。
- 另外，`pcap_next()` 和 `pcap_next_ex()` 函数用来捕获单个数据包

**关闭网络设备**

- `pcap_close()`: 关闭已打开的网络设备并释放资源。





### Libpcap

**设备发现**

- `pcap_findalldevs()`: 获取本地机器上所有网络设备的列表。

**网络设备设置**

- `pcap_open_live()`用于打开指定的网络设备，并且返回用于捕获网络数据包的数据包捕获描述字。对于此网络设备的操作都要基于此网络设备描述字。
- `pcap_lookupnet()`: 获取指定网络设备的网络号和掩码。

**设置过滤器**

- `pcap_compile()`: 将用户指定的过滤策略编译为过滤程序。

- `pcap_setfilter()`: 将编译后的过滤程序设置到 pcap 句柄。

**数据包捕获**

- `pcap_loop()` 或 `pcap_dispatch()`: 捕获数据包并调用指定的回调函数进行处理。
- `pcap_next()` 和 `pcap_next_ex()`: 捕获单个数据包。

**关闭网络设备**

- `pcap_close()`: 关闭已打开的网络设备并释放资源。