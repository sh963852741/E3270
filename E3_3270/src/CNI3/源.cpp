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
#define THRESHOLD 1024	//������ֵ����λbyte
#define INTERVAL 6		//����ͳ�Ƶ�ʱ��������λs

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

/* ��ͬMAC��ַ */
typedef struct Node{
	u_char mac_addr[6];	//MAC
	u_char ip_addr[4];	//IP
	int size;
	Node *next;
}Node;

/* �����ص����� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* ����Node�ĳ�ʼ������ */
void Init(Node *p, u_char* ip, u_char* mac, u_int len);

/* ����Node�ıȽϺ��� */
void Nodecmp(Node *head, Node *p);

/* ����u_char�ıȽϺ��� */
//int u_charcmp(u_char *c1, u_char *c2);

/* ������ñ���mac�ĺ��� */
void getLocalMac(char *name);

static int total = 0;	//������
static int status = 0;	//�Ƿ��ѳ�����ֵ
static int st = 0;		//��һ�λ�ȡʱ��ı�־		

struct tm *otime;
char o_timestr[16];
time_t old_tv_sec;		//�ϴε�ϵͳʱ�䣬���ڼ���ʱ������ͳ������

u_char mac[6];			//��ѡ������mac��ַ

Node *src_head = (Node*)malloc(sizeof(Node));	//�������ݵ�����
Node *dest_head = (Node*)malloc(sizeof(Node));	//�յ����ݵ�����


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
	char name[39];
	for (int i = 0; i < 39; i++)
		name[i] = d->name[i + 12];

	//�����ѡ������mac
	getLocalMac(name);
	/*printf("%02X-%02X-%02X-%02X-%02X-%02X,", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);*/

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	src_head->next = NULL;
	dest_head->next = NULL;

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 0, packet_handler, (PUCHAR)&st_ts);
	
	return 0;
}

/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if (st == 0) { old_tv_sec = header->ts.tv_sec; st = 1; }
	ip_header *ih;
	mac_header* mh;
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	total += header->caplen;// ʵ�ʲ��񳤶ȣ���λbyte

	/* ������ֵ��Ԥ�� */
	if (status == 0 && total > THRESHOLD) {
		printf("Warning: exceed the threshold %d byte\n", THRESHOLD);
		status = 1;
	}

	/* ���MAC֡ */
	mh = (mac_header*)pkt_data;

	/* ���IP���ݰ�ͷ����λ�� */
	ih = (ip_header *)(pkt_data +
		14); //��̫��ͷ������

	/* ��ʱ���ת��Ϊ��ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);


	/* ��¼���ͷ�����շ���MAC��IP��ַ */
	FILE *fp;
	fopen_s(&fp, "..\\..\\bin\\Log\\records.csv", "ab");
	//��ӡʱ��
	fprintf(fp,"%4d-%02d-%02d ", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday);
	fprintf(fp,"%s,", timestr);
	//��ӡԴMAC��ԴIP
	fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,", mh->src_addr[0], mh->src_addr[1], mh->src_addr[2], mh->src_addr[3], mh->src_addr[4], mh->src_addr[5]);
	fprintf(fp,"%d.%d.%d.%d,", ih->saddr.addr[0], ih->saddr.addr[1], ih->saddr.addr[2], ih->saddr.addr[3]);
	//��ӡĿ��MAC��Ŀ��IP
	fprintf(fp,"%02X-%02X-%02X-%02X-%02X-%02X,", mh->dest_addr[0], mh->dest_addr[1], mh->dest_addr[2], mh->dest_addr[3], mh->dest_addr[4], mh->dest_addr[5]);
	fprintf(fp,"%d.%d.%d.%d,", ih->daddr.addr[0], ih->daddr.addr[1], ih->daddr.addr[2], ih->daddr.addr[3]);
	//��ӡ֡����
	fprintf(fp,"%d\r\n", header->len);
	fclose(fp);

	/* ���С��1minʱͳ�Ʒ�������ܵ�ͨѶ���ݳ��� */
	if (local_tv_sec - old_tv_sec < INTERVAL) {
		Node *p_src = new Node();		//ԴmacΪ����mac
		Node *p_dest = new Node();		//Ŀ��macΪ����mac
		int s_mac = 0;
		for (int i = 0; i < 6; i++) {
			if (mac[i] ^ mh->src_addr[i])
				s_mac = -1;
		}

		//������ͬMAC��ͨ�����ݳ���
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
		
		//�����Բ�ͬMAC��ͨ�����ݳ���
		if (s_mac == 1) {
			Init(p_dest, ih->saddr.addr, mh->src_addr, header->len);
			if (dest_head->next == NULL) dest_head->next = p_dest; 
			else Nodecmp(dest_head, p_dest); 
		}
	}

	/* ������ڵ���1minʱ��¼ͨѶ���ݳ��� */
	else {
		FILE *fp;
		fopen_s(&fp, "..\\..\\bin\\Log\\src.csv", "ab");

		/* ���ϴε�ʱ���ת��Ϊ��ʶ��ĸ�ʽ */
		otime = localtime(&old_tv_sec);
		strftime(o_timestr, sizeof o_timestr, "%H:%M:%S", otime);

		/* �����Բ�ͬMAC��ͨ�����ݳ��� */
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

		/* ������ͬMAC��ͨ�����ݳ��� */
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
		old_tv_sec = local_tv_sec;	//�����ϴ�ʱ��
	}
}

/* Node��ʼ�� */
void Init(Node *p, u_char* ip, u_char* cmac, u_int len) {
	p->next = NULL;
	//���mac��ַ
	for (int i = 0; i < 6; i++) 
		p->mac_addr[i] = cmac[i];
	
	//���ip��ַ
	for (int i = 0; i < 4; i++)
		p->ip_addr[i] = ip[i];
	//������ݳ���
	p->size = len;
}

/* Node�ıȽϺ������ж�*head���Ƿ������ͬmac��Node */
void Nodecmp(Node *head, Node *p) {
	int s = 0;
	//����*head���Ƚ�mac��ַ

	for (Node *temp = head; temp->next != NULL;) {
		temp = temp->next;
		if (strcmp((char*)temp->mac_addr, (char*)p->mac_addr) == 0) {
			//�ýڵ��mac��p��ͬ
			temp->size += p->size;
			free(p);
			return;
		}
	}
	//������mac��ͬ��Node
	p->next = head->next;
	head->next = p;
}

//int u_charcmp(u_char *c1, u_char *c2) {
//	for (int i = 0; i < 6; i++)
//		if (!(c2[i]^c1[i])) return -1;
//	return 0;
//}

/* ��ñ���mac */
void getLocalMac(char *name) {
	int count = 0;	//����mac[]����
	//PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//�õ��ṹ���С,����GetAdaptersInfo����
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);

	if (ERROR_BUFFER_OVERFLOW == nRel){
		//����������ص���ERROR_BUFFER_OVERFLOW
	   //��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		//��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
		//�ͷ�ԭ�����ڴ�ռ�
		delete pIpAdapterInfo;
		//���������ڴ�ռ������洢����������Ϣ
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
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
	//�ͷ��ڴ�ռ�
	if (pIpAdapterInfo)delete pIpAdapterInfo;
}
