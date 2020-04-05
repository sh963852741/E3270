#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <iostream>
#include <fstream>
#include "pcap.h"

#include <Iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "Iphlpapi")
#pragma comment(lib, "WS2_32")

/* 4�ֽڵ�IP��ַ */
typedef struct ip_address
{
	u_char addr[4];
}ip_address;

/* IPv4 �ײ� */
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

/* TCP�ײ� */
typedef struct tcp_header
{
	u_short sport;			// Դ�˿ں�  
	u_short dport;			// Ŀ�Ķ˿ں�
	u_int th_seq;			// ���  
	u_int th_ack;			// ȷ�Ϻ�  
	u_int th1 : 4;			// ����ƫ��  
	u_int th_res : 4;		// 6λ�е�4λ 
	u_int th_res2 : 2;		// 6λ�е�2λ
	u_char th_flags;		// 6λ��־λ  
	u_short th_win;			// ���ڴ�С  
	u_short th_sum;			// �����  
	u_short th_urp;			// ����ָ��  
}tcp_header;

/* UDP �ײ�*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* MAC֡ */
typedef struct mac_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* �û���¼��Ϣ */
typedef struct Info{
	char user[20];			//�û���
	char pass[20];			// ����
	bool status;			//�Ƿ��¼�ɹ�
}Info;

/* �����ص����� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

Info info;		//��ȡ��ǰ�û�


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



	/* ����豸�б� */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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

		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open_live(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ��� 
				   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		0,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		errbuf     // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//�����ѡ����������
	char name[38];
	for (int i = 0; i < 39; i++)
		name[i] = d->name[i + 12];

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 0, packet_handler, (PUCHAR)&st_ts);
	
	return 0;
}

/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header *ih;
	tcp_header *th;
	mac_header *mh;
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	int head = 54;			//ָ�ͷ

	/* ���MAC֡ */
	mh = (mac_header *)pkt_data;

	/* ���IP���ݰ�ͷ����λ�� */
	ih = (ip_header *)(pkt_data +
		14); //��̫��ͷ������

	/* ���TCP */
	th = (tcp_header *)(pkt_data +
		34);

	/* ��ʱ���ת��Ϊ��ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* ����û��� */
	if ((char)pkt_data[head] == 'U') {
		int count = 0;
		for (int i = head + 5; pkt_data[i] != '\r'; i++)
			info.user[count++] = (char)pkt_data[i];
		info.user[count++] = '\0';
	}

	/* ������� */
	else if ((char)pkt_data[head] == 'P') {
		int count = 0;
		for (int i = head + 5; pkt_data[i] != '\r'; i++)
			info.pass[count++] = (char)pkt_data[i];
		info.pass[count++] = '\0';
	}

	/* ��õ�¼״̬����ӡ */
	else if ((char)pkt_data[head+1] == '3' && (char)pkt_data[head+2] == '0'){
		// "230"��ʾ��¼�ɹ�
		if ((char)pkt_data[head] == '2')
			info.status = true;
		// "530"��ʾ��¼�ɹ�
		else if ((char)pkt_data[head] == '5')
			info.status = false;
		// �ų��������
		else 
			return;

		/* ��¼���ͷ�����շ���MAC��IP��ַ */
		FILE *fp;
		fopen_s(&fp, "..\\..\\bin\\Log\\records.csv", "ab");
		//��ӡʱ��
		fprintf(fp, "%4d-%02d-%02d ", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday);
		fprintf(fp, "%s,", timestr);
		//��ӡԴMAC��ԴIP
		fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", mh->src_addr[0], mh->src_addr[1], mh->src_addr[2], mh->src_addr[3], mh->src_addr[4], mh->src_addr[5]);
		fprintf(fp, "%d.%d.%d.%d,", ih->saddr.addr[0], ih->saddr.addr[1], ih->saddr.addr[2], ih->saddr.addr[3]);
		//��ӡĿ��MAC��Ŀ��IP
		fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,", mh->dest_addr[0], mh->dest_addr[1], mh->dest_addr[2], mh->dest_addr[3], mh->dest_addr[4], mh->dest_addr[5]);
		fprintf(fp, "%d.%d.%d.%d,", ih->daddr.addr[0], ih->daddr.addr[1], ih->daddr.addr[2], ih->daddr.addr[3]);
		//��ӡ�û���Ϣ
		for (int i = 0; info.user[i] != '\0'; i++)
			fprintf(fp, "%c", info.user[i]);	//�û���
		fprintf(fp, ",");
		for (int i = 0; info.pass[i] != '\0'; i++)
			fprintf(fp, "%c", info.pass[i]);	//����
		fprintf(fp, ",");
		if (info.status == true)
			fprintf(fp, "SUCCEED\r");			//��¼״̬
		else
			fprintf(fp, "FAILED\r");
		fclose(fp);

		/* ʵ��Ҫ����������� Ҫ��һ�� */
		fopen_s(&fp, "..\\..\\bin\\Log\\ftp_records.csv", "ab");
		//��ӡFTP��IP
		fprintf(fp, "FTP:");
		fprintf(fp, "%d.%d.%d.%d,", ih->saddr.addr[0], ih->saddr.addr[1], ih->saddr.addr[2], ih->saddr.addr[3]);
		//��ӡ�û���Ϣ
		fprintf(fp, "USR:");
		for (int i = 0; info.user[i] != '\0'; i++)
			fprintf(fp, "%c", info.user[i]);	//�û���
		fprintf(fp, ",");
		fprintf(fp, "PAS:");
		for (int i = 0; info.pass[i] != '\0'; i++)
			fprintf(fp, "%c", info.pass[i]);	//����
		fprintf(fp, ",");
		fprintf(fp, "STA:");
		if (info.status == true)
			fprintf(fp, "SUCCEED\r");			//��¼״̬
		else
			fprintf(fp, "FAILED\r");
		fclose(fp);
	}
}