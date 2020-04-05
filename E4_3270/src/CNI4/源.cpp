#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <iostream>
#include <fstream>
#include "pcap.h"

#include <Iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "Iphlpapi")
#pragma comment(lib, "WS2_32")

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

/* TCP首部 */
typedef struct tcp_header
{
	u_short sport;			// 源端口号  
	u_short dport;			// 目的端口号
	u_int th_seq;			// 序号  
	u_int th_ack;			// 确认号  
	u_int th1 : 4;			// 数据偏移  
	u_int th_res : 4;		// 6位中的4位 
	u_int th_res2 : 2;		// 6位中的2位
	u_char th_flags;		// 6位标志位  
	u_short th_win;			// 窗口大小  
	u_short th_sum;			// 检验和  
	u_short th_urp;			// 紧急指针  
}tcp_header;

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

/* 用户登录信息 */
typedef struct Info{
	char user[20];			//用户名
	char pass[20];			// 密码
	bool status;			//是否登录成功
}Info;

/* 申明回调函数 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

Info info;		//存取当前用户


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";
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
	char name[38];
	for (int i = 0; i < 39; i++)
		name[i] = d->name[i + 12];

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕捉 */
	pcap_loop(adhandle, 0, packet_handler, (PUCHAR)&st_ts);
	
	return 0;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header *ih;
	tcp_header *th;
	mac_header *mh;
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	int head = 54;			//指令开头

	/* 获得MAC帧 */
	mh = (mac_header *)pkt_data;

	/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data +
		14); //以太网头部长度

	/* 获得TCP */
	th = (tcp_header *)(pkt_data +
		34);

	/* 将时间戳转化为可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 获得用户名 */
	if ((char)pkt_data[head] == 'U') {
		int count = 0;
		for (int i = head + 5; pkt_data[i] != '\r'; i++)
			info.user[count++] = (char)pkt_data[i];
		info.user[count++] = '\0';
	}

	/* 获得密码 */
	else if ((char)pkt_data[head] == 'P') {
		int count = 0;
		for (int i = head + 5; pkt_data[i] != '\r'; i++)
			info.pass[count++] = (char)pkt_data[i];
		info.pass[count++] = '\0';
	}

	/* 获得登录状态并打印 */
	else if ((char)pkt_data[head+1] == '3' && (char)pkt_data[head+2] == '0'){
		// "230"表示登录成功
		if ((char)pkt_data[head] == '2')
			info.status = true;
		// "530"表示登录成功
		else if ((char)pkt_data[head] == '5')
			info.status = false;
		// 排除其他情况
		else 
			return;

		/* 记录发送方与接收方的MAC和IP地址 */
		FILE *fp;
		fopen_s(&fp, "..\\..\\bin\\Log\\records.csv", "ab");
		//打印时间
		fprintf(fp, "%4d-%02d-%02d ", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday);
		fprintf(fp, "%s,", timestr);
		//打印源MAC、源IP
		fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", mh->src_addr[0], mh->src_addr[1], mh->src_addr[2], mh->src_addr[3], mh->src_addr[4], mh->src_addr[5]);
		fprintf(fp, "%d.%d.%d.%d,", ih->saddr.addr[0], ih->saddr.addr[1], ih->saddr.addr[2], ih->saddr.addr[3]);
		//打印目标MAC、目标IP
		fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", mh->dest_addr[0], mh->dest_addr[1], mh->dest_addr[2], mh->dest_addr[3], mh->dest_addr[4], mh->dest_addr[5]);
		fprintf(fp, "%d.%d.%d.%d,", ih->daddr.addr[0], ih->daddr.addr[1], ih->daddr.addr[2], ih->daddr.addr[3]);
		//打印用户信息
		for (int i = 0; info.user[i] != '\0'; i++)
			fprintf(fp, "%c", info.user[i]);	//用户名
		fprintf(fp, ",");
		for (int i = 0; info.pass[i] != '\0'; i++)
			fprintf(fp, "%c", info.pass[i]);	//密码
		fprintf(fp, ",");
		if (info.status == true)
			fprintf(fp, "SUCCEED\r");			//登录状态
		else
			fprintf(fp, "FAILED\r");
		fclose(fp);

		/* 实验要求与操作步骤 要求不一致 */
		fopen_s(&fp, "..\\..\\bin\\Log\\ftp_records.csv", "ab");
		//打印FTP的IP
		fprintf(fp, "FTP:");
		fprintf(fp, "%d.%d.%d.%d,", ih->saddr.addr[0], ih->saddr.addr[1], ih->saddr.addr[2], ih->saddr.addr[3]);
		//打印用户信息
		fprintf(fp, "USR:");
		for (int i = 0; info.user[i] != '\0'; i++)
			fprintf(fp, "%c", info.user[i]);	//用户名
		fprintf(fp, ",");
		fprintf(fp, "PAS:");
		for (int i = 0; info.pass[i] != '\0'; i++)
			fprintf(fp, "%c", info.pass[i]);	//密码
		fprintf(fp, ",");
		fprintf(fp, "STA:");
		if (info.status == true)
			fprintf(fp, "SUCCEED\r");			//登录状态
		else
			fprintf(fp, "FAILED\r");
		fclose(fp);
	}
}