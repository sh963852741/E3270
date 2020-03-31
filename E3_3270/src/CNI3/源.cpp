#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <iostream>
#include <fstream>
#include "pcap.h"

#include <Iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "Iphlpapi")
#pragma comment(lib, "WS2_32")


using namespace std;
#define THRESHOLD 1024	//警告阈值，单位byte
#define INTERVAL 6		//流量统计的时间间隔，单位s

/* 4字节的IP地址 */
typedef struct ip_address
{
	u_char addr[4];
}ip_address;

/* IPv4 首部 */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP 首部*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* MAC帧 */
typedef struct mac_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* 相同MAC地址 */
typedef struct Node{
	u_char mac_addr[6];	//MAC
	u_char ip_addr[4];	//IP
	int size;
	Node *next;
}Node;

/* 申明回调函数 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* 申明Node的初始化函数 */
void Init(Node *p, u_char* ip, u_char* mac, u_int len);

/* 申明Node的比较函数 */
void Nodecmp(Node *head, Node *p);

/* 申明u_char的比较函数 */
//int u_charcmp(u_char *c1, u_char *c2);

/* 申明获得本机mac的函数 */
void getLocalMac(char *name);

static int total = 0;	//总流量
static int status = 0;	//是否已超过阈值
static int st = 0;		//第一次获取时间的标志		

struct tm *otime;
char o_timestr[16];
time_t old_tv_sec;		//上次的系统时间，用于计算时间间隔、统计流量

u_char mac[6];			//所选网卡的mac地址

Node *src_head = (Node*)malloc(sizeof(Node));	//发出数据的链表
Node *dest_head = (Node*)malloc(sizeof(Node));	//收到数据的链表


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	struct timeval st_ts;



	/* 获得设备列表 */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开适配器 */
	if ((adhandle = pcap_open_live(d->name,  // 设备名
		65536,     // 要捕捉的数据包的部分 
				   // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		0,         // 混杂模式
		1000,      // 读取超时时间
		errbuf     // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//获得所选网卡的名称
	char name[39];
	for (int i = 0; i < 39; i++)
		name[i] = d->name[i + 12];

	//获得所选网卡的mac
	getLocalMac(name);
	/*printf("%02X-%02X-%02X-%02X-%02X-%02X,", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);*/

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	src_head->next = NULL;
	dest_head->next = NULL;

	/* 开始捕捉 */
	pcap_loop(adhandle, 0, packet_handler, (PUCHAR)&st_ts);
	
	return 0;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if (st == 0) { old_tv_sec = header->ts.tv_sec; st = 1; }
	ip_header *ih;
	mac_header* mh;
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	total += header->caplen;// 实际捕获长度，单位byte

	/* 超过阈值则预警 */
	if (status == 0 && total > THRESHOLD) {
		printf("Warning: exceed the threshold %d byte\n", THRESHOLD);
		status = 1;
	}

	/* 获得MAC帧 */
	mh = (mac_header*)pkt_data;

	/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data +
		14); //以太网头部长度

	/* 将时间戳转化为可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);


	/* 记录发送方与接收方的MAC和IP地址 */
	FILE *fp;
	fopen_s(&fp, "..\\..\\bin\\Log\\records.csv", "ab");
	//打印时间
	fprintf(fp,"%4d-%02d-%02d ", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday);
	fprintf(fp,"%s,", timestr);
	//打印源MAC、源IP
	fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,", mh->src_addr[0], mh->src_addr[1], mh->src_addr[2], mh->src_addr[3], mh->src_addr[4], mh->src_addr[5]);
	fprintf(fp,"%d.%d.%d.%d,", ih->saddr.addr[0], ih->saddr.addr[1], ih->saddr.addr[2], ih->saddr.addr[3]);
	//打印目标MAC、目标IP
	fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,", mh->dest_addr[0], mh->dest_addr[1], mh->dest_addr[2], mh->dest_addr[3], mh->dest_addr[4], mh->dest_addr[5]);
	fprintf(fp,"%d.%d.%d.%d,", ih->daddr.addr[0], ih->daddr.addr[1], ih->daddr.addr[2], ih->daddr.addr[3]);
	//打印帧长度
	fprintf(fp,"%d\r\n", header->len);
	fclose(fp);

	/* 间隔小于1min时统计发送与接受的通讯数据长度 */
	if (local_tv_sec - old_tv_sec < INTERVAL) {
		Node *p_src = new Node();		//源mac为本机mac
		Node *p_dest = new Node();		//目的mac为本机mac
		int s_mac = 0;
		for (int i = 0; i < 6; i++) {
			if (mac[i] ^ mh->src_addr[i])
				s_mac = -1;
		}

		//发至不同MAC的通信数据长度
		if (s_mac == 0) {
			Init(p_src, ih->daddr.addr, mh->dest_addr, header->len);
			if (src_head->next == NULL) src_head->next = p_src;
			else Nodecmp(src_head, p_src);
		}
		
		s_mac = 1;

		for (int i = 0; i < 6; i++) {
			if (mac[i] != mh->dest_addr[i])
				s_mac = -1;
		}
		
		//接收自不同MAC的通信数据长度
		if (s_mac == 1) {
			Init(p_dest, ih->saddr.addr, mh->src_addr, header->len);
			if (dest_head->next == NULL) dest_head->next = p_dest; 
			else Nodecmp(dest_head, p_dest); 
		}
	}

	/* 间隔大于等于1min时记录通讯数据长度 */
	else {
		FILE *fp;
		fopen_s(&fp, "..\\..\\bin\\Log\\src.csv", "ab");

		/* 将上次的时间戳转化为可识别的格式 */
		otime = localtime(&old_tv_sec);
		strftime(o_timestr, sizeof o_timestr, "%H:%M:%S", otime);

		/* 接收自不同MAC的通信数据长度 */
		fprintf(fp, "%4d-%02d-%02d ", otime->tm_year + 1900, otime->tm_mon + 1, otime->tm_mday);
		fprintf(fp, "%s,", o_timestr);
		fprintf(fp, "%4d-%02d-%02d ", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday);
		fprintf(fp, "%s\n", timestr);
		for (Node *temp = dest_head; temp->next != NULL;) {
			temp = temp->next;
			fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,", temp->mac_addr[0], temp->mac_addr[1], temp->mac_addr[2], temp->mac_addr[3], temp->mac_addr[4], temp->mac_addr[5]);
			fprintf(fp,"%d.%d.%d.%d,", temp->ip_addr[0], temp->ip_addr[1], temp->ip_addr[2], temp->ip_addr[3]);
			fprintf(fp,"%d\n", temp->size);
		}
		fprintf(fp, "\n");
		fclose(fp);

		/* 发至不同MAC的通信数据长度 */
		fopen_s(&fp, "..\\..\\bin\\Log\\dest.csv", "ab");
		fprintf(fp, "%4d-%02d-%02d ", otime->tm_year + 1900, otime->tm_mon + 1, otime->tm_mday);
		fprintf(fp, "%s,", o_timestr);
		fprintf(fp, "%4d-%02d-%02d ", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday);
		fprintf(fp, "%s\n", timestr);
		for (Node *temp = src_head; temp->next != NULL;) {
			temp = temp->next;
			fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", temp->mac_addr[0], temp->mac_addr[1], temp->mac_addr[2], temp->mac_addr[3], temp->mac_addr[4], temp->mac_addr[5]);
			fprintf(fp, "%d.%d.%d.%d,", temp->ip_addr[0], temp->ip_addr[1], temp->ip_addr[2], temp->ip_addr[3]);
			fprintf(fp, "%d\n", temp->size);
		}
		fprintf(fp, "\n");
		fclose(fp);
		old_tv_sec = local_tv_sec;	//重置上次时间
	}
}

/* Node初始化 */
void Init(Node *p, u_char* ip, u_char* cmac, u_int len) {
	p->next = NULL;
	//获得mac地址
	for (int i = 0; i < 6; i++) 
		p->mac_addr[i] = cmac[i];
	
	//获得ip地址
	for (int i = 0; i < 4; i++)
		p->ip_addr[i] = ip[i];
	//获得数据长度
	p->size = len;
}

/* Node的比较函数，判断*head里是否存在相同mac的Node */
void Nodecmp(Node *head, Node *p) {
	int s = 0;
	//遍历*head，比较mac地址

	for (Node *temp = head; temp->next != NULL;) {
		temp = temp->next;
		if (strcmp((char*)temp->mac_addr, (char*)p->mac_addr) == 0) {
			//该节点的mac与p相同
			temp->size += p->size;
			free(p);
			return;
		}
	}
	//不存在mac相同的Node
	p->next = head->next;
	head->next = p;
}

//int u_charcmp(u_char *c1, u_char *c2) {
//	for (int i = 0; i < 6; i++)
//		if (!(c2[i]^c1[i])) return -1;
//	return 0;
//}

/* 获得本机mac */
void getLocalMac(char *name) {
	int count = 0;	//用于mac[]计数
	//PIP_ADAPTER_INFO结构体指针存储本机网卡信息
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//得到结构体大小,用于GetAdaptersInfo参数
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);

	if (ERROR_BUFFER_OVERFLOW == nRel){
		//如果函数返回的是ERROR_BUFFER_OVERFLOW
	   //则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		//这也是说明为什么stSize既是一个输入量也是一个输出量
		//释放原来的内存空间
		delete pIpAdapterInfo;
		//重新申请内存空间用来存储所有网卡信息
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}

	if (ERROR_SUCCESS == nRel){
		while (pIpAdapterInfo)
		{
			if (strcmp(pIpAdapterInfo->AdapterName, name) == 0) {
				for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++) 
					mac[count++] = pIpAdapterInfo->Address[i];			
			}
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
	//释放内存空间
	if (pIpAdapterInfo)delete pIpAdapterInfo;
}
