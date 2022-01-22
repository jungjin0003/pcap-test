#include <stdio.h>
#include <string.h>
#include <pcap.h>

#define FALSE 0
#define TRUE 1

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

typedef struct _Ethernet
{
    BYTE Dst[6];
    BYTE Src[6];
    WORD Type;
} Ethernet;

typedef struct _IP
{
    BYTE Version        : 4;
    BYTE HeaderLength   : 4;
    BYTE DifferentiatedServicesField;
    WORD TotalLength;
    WORD Identification;
    BYTE Flags;
    BYTE FragmentOffset;
    BYTE TimeToLive;
    BYTE Protocol;
    WORD CheckSum;
    union
    {
        struct
        {
            BYTE s_b1;
            BYTE s_b2;
            BYTE s_b3;
            BYTE s_b4;
        } S_un_b;
        DWORD S_addr;
    } Src;
    union
    {
        struct
        {
            BYTE s_b1;
            BYTE s_b2;
            BYTE s_b3;
            BYTE s_b4;
        } S_un_b;
        DWORD S_addr;
    } Dst;
} IP;

typedef struct _TCP
{
    WORD SrcPort;
    WORD DstPort;
    DWORD SequenceNumber;
    DWORD AcknowledgmentNumber;
    BYTE Nonce          : 1;
    BYTE Reserved       : 3;
    BYTE HeaderLength   : 4;
    BYTE Fin            : 1;
    BYTE Syn            : 1;
    BYTE Reset          : 1;
    BYTE Push           : 1;
    BYTE Acknowledgment : 1;
    BYTE Urgent         : 1;
    BYTE ECN            : 1;
    BYTE CWR            : 1;
    WORD WindowSize;
    WORD CheckSum;
    WORD UrgentPointer;
} TCP;

typedef struct _TCP_Option
{
    BYTE Kind;
    BYTE Length;
    BYTE Data[1];
} TCP_Option;

void ParseEthernetHeader(const BYTE *__packet, Ethernet *__ethernet)
{
    Ethernet *ethernet = __packet;
    
    *__ethernet = *ethernet;
    __ethernet->Type = ntohs(__ethernet->Type);
}

void ParseIpHeader(const BYTE *__packet, IP *__ip)
{
    IP *ip = __packet + sizeof(Ethernet);

    memcpy(__ip, ip, sizeof(IP));
    __ip->Version = ip->HeaderLength;
    __ip->HeaderLength = ip->Version;
    __ip->TotalLength = ntohs(__ip->TotalLength);
    __ip->Identification = ntohs(__ip->Identification);
    __ip->CheckSum = ntohs(__ip->CheckSum);
}

void ParseTcpHeader(const BYTE *__packet, TCP *__tcp)
{
    IP ip;
    ParseIpHeader(__packet, &ip);

    TCP *tcp = __packet + sizeof(Ethernet) + (ip.HeaderLength * 4);

    memcpy(__tcp, tcp, sizeof(TCP));
    __tcp->SrcPort = ntohs(__tcp->SrcPort);
    __tcp->DstPort = ntohs(__tcp->DstPort);
    __tcp->SequenceNumber = ntohl(__tcp->SequenceNumber);
    __tcp->AcknowledgmentNumber = ntohl(__tcp->AcknowledgmentNumber);
    __tcp->WindowSize = ntohs(__tcp->WindowSize);
    __tcp->CheckSum = ntohs(__tcp->CheckSum);
    __tcp->UrgentPointer = ntohs(__tcp->UrgentPointer);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("usage : pcap-test <interface>\n");
        printf("sample : pcap-test wlan0\n");
        return -1;
    }

	char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
    }

    while (TRUE)
    {
        struct pcap_pkthdr *header;
        const unsigned char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }
        
        Ethernet ethernet;
        ParseEthernetHeader(packet, &ethernet);
        IP ip;
        ParseIpHeader(packet, &ip);
        TCP tcp;
        ParseTcpHeader(packet, &tcp);
        BYTE *Payload = packet + sizeof(Ethernet) + (ip.HeaderLength * 4) + (tcp.HeaderLength * 4);
        if (ip.Protocol != 0x06)
            continue;
        printf("Src MAC : [%02x:%02x:%02x:%02x:%02x:%02x], ", ethernet.Src[0], ethernet.Src[1], ethernet.Src[2], ethernet.Src[3], ethernet.Src[4], ethernet.Src[5]);
        printf("Dst MAC : [%02x:%02x:%02x:%02x:%02x:%02x]\n", ethernet.Dst[0], ethernet.Dst[1], ethernet.Dst[2], ethernet.Dst[3], ethernet.Dst[4], ethernet.Dst[5]);
        printf("Src IP : [%d.%d.%d.%d], ", ip.Src.S_un_b.s_b1, ip.Src.S_un_b.s_b2, ip.Src.S_un_b.s_b3, ip.Src.S_un_b.s_b4);
        printf("Dst IP : [%d.%d.%d.%d]\n", ip.Dst.S_un_b.s_b1, ip.Dst.S_un_b.s_b2, ip.Dst.S_un_b.s_b3, ip.Dst.S_un_b.s_b4);
        printf("Src Port : %d, ", tcp.SrcPort);
        printf("Dst Port : %d\n", tcp.DstPort);
        for (int i = 0; i < 8; i++)
        {
            if (i < ip.TotalLength - ((ip.HeaderLength * 4) + (tcp.HeaderLength * 4)))
            {
                printf("%02x ", Payload[i]);
            }
            else
            {
                printf("XX ");
            }
        }
        putchar('\n');
    }

    pcap_close(pcap);
}