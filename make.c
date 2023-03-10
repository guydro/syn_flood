
#include "stdio.h"
#include "winsock2.h"
#include "ws2tcpip.h" //IP_HDRINCL is here
#include <stdint.h>
#include <netioapi.h>


#define host_port 3389
#define dst_port 3389

typedef struct __attribute__((__packed__)) ip_hdr
{
    unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    unsigned char ip_version :4; // 4-bit IPv4 version
    unsigned char ip_tos; // IP type of service
    unsigned short ip_total_length; // Total length
    unsigned short ip_id; // Unique identifier

    unsigned char ip_frag_offset :5; // Fragment offset field

    unsigned char ip_more_fragment :1;
    unsigned char ip_dont_fragment :1;
    unsigned char ip_reserved_zero :1;

    unsigned char ip_frag_offset1; //fragment offset

    unsigned char ip_ttl; // Time to live
    unsigned char ip_protocol; // Protocol(TCP,UDP etc)
    unsigned short ip_checksum; // IP checksum
    unsigned int ip_srcaddr; // Source address
    unsigned int ip_destaddr; // Source address
} IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR;

// TCP header
typedef struct tcp_header
{
    unsigned short source_port; // source port
    unsigned short dest_port; // destination port
    unsigned int sequence; // sequence number - 32 bits
    unsigned int acknowledge; // acknowledgement number - 32 bits

    unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
    unsigned char reserved_part1:3; //according to rfc
    unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
This indicates where the data begins.
The length of the TCP header is always a multiple
of 32 bits.*/

    unsigned char fin :1; //Finish Flag
    unsigned char syn :1; //Synchronise Flag
    unsigned char rst :1; //Reset Flag
    unsigned char psh :1; //Push Flag
    unsigned char ack :1; //Acknowledgement Flag
    unsigned char urg :1; //Urgent Flag

    unsigned char ecn :1; //ECN-Echo Flag
    unsigned char cwr :1; //Congestion Window Reduced Flag

////////////////////////////////

    unsigned short window; // window
    unsigned short checksum; // checksum
    unsigned short urgent_pointer; // urgent pointer
} TCP_HDR , *PTCP_HDR , FAR * LPTCP_HDR , TCPHeader , TCP_HEADER;

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcp_header tcp;
};

struct pseudoTcpHeader
{
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned char zero;//always zero
    unsigned char protocol;// = 6;//for tcp
    unsigned short tcp_len;
    struct tcp_header tcph;
};

unsigned short TcpCheckSum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main()
{
    setbuf(stdout, 0);

    char buf[1000],*data=NULL; //buf is the complete packet
    SOCKET s;

    IPV4_HDR *v4hdr=NULL;
    TCP_HDR *tcphdr=NULL;

    int payload=100;
    SOCKADDR_IN dest;
    struct hostent *server;

//Initialise Winsock
    WSADATA wsock;
    printf("\r\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsock) != 0)
    {
        fprintf(stderr,"WSAStartup() failed");
        exit(EXIT_FAILURE);
    }
    printf("Initialised successfully.");
////////////////////////////////////////////////

//Create Raw TCP Packet
    printf("\r\nCreating Raw TCP Socket...");
    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))==SOCKET_ERROR)
    {
        printf("Creation of raw socket failed.");
        return 0;
    }

    printf("Raw TCP Socket Created successfully.");
//////////////////////////////////////////////

//Put Socket in RAW Mode.
    printf("\nSetting the socket in RAW mode...");
    int on = 1;
    int error =  setsockopt(s,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    if (error == SOCKET_ERROR)
    {
        printf("Error setsockopt(): %d", WSAGetLastError());
        return -1;
    }


////////////////////////////////////////////////


//Target Hostname
    char* host = "192.168.0.2";
    printf("\nResolving Hostname...");
    if((server=gethostbyname(host))==0)
    {
        printf("Unable to resolve.");
        return 0;
    }



    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port); //your destination port
    memcpy(&dest.sin_addr.s_addr,server->h_addr,server->h_length);
    printf("Resolved.");
/////////////////////////////////////////////////


    char* source_ip = "192.168.0.9";
    printf("\nInitialized source ip");

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(host_port);
    inet_aton(source_ip, &bind_addr.sin_addr.s_addr);
    bind(s, (struct sockaddr*) &bind_addr, sizeof(bind_addr));

    v4hdr = (IPV4_HDR *)buf; //let's point to the ip header portion
    v4hdr->ip_version=4;
    v4hdr->ip_header_len=5;
    v4hdr->ip_tos = 0;
    v4hdr->ip_total_length = htons ( sizeof(IPV4_HDR) + sizeof(TCP_HDR) + payload );
    v4hdr->ip_id = htons(2);
    v4hdr->ip_frag_offset = 0;
    v4hdr->ip_frag_offset1 = 0;
    v4hdr->ip_reserved_zero = 0;
    v4hdr->ip_dont_fragment = 1;
    v4hdr->ip_more_fragment = 0;
    v4hdr->ip_ttl = 100;
    v4hdr->ip_protocol = IPPROTO_TCP;
    v4hdr->ip_srcaddr = inet_addr(source_ip);
    v4hdr->ip_destaddr = inet_addr(inet_ntoa(dest.sin_addr));
    v4hdr->ip_checksum = csum( (unsigned short*) &v4hdr , sizeof (struct pseudo_header));


    tcphdr = (TCP_HDR *)&buf[sizeof(IPV4_HDR)]; //get the pointer to the tcp header in the packet

    tcphdr->source_port = htons(host_port);
    tcphdr->dest_port = htons(dst_port);

    tcphdr->sequence = 0xABCDEFAB;

    tcphdr->data_offset = 5;

    tcphdr->cwr=0;
    tcphdr->ecn=0;
    tcphdr->urg=0;
    tcphdr->ack=0;
    tcphdr->psh=0;
    tcphdr->rst=0;
    tcphdr->syn=1;
    tcphdr->fin=0;
    tcphdr->ns=0;

    tcphdr->checksum = TcpCheckSum((short unsigned int*)tcphdr, sizeof(TCP_HDR));


// Initialize the TCP payload to some rubbish
    data = &buf[sizeof(IPV4_HDR) + sizeof(TCP_HDR)];
    memset(data, '\0', payload);


    printf("\nSending packet...\n");


    int i=0;
    while(1)
    {
        int result = sendto(s, buf, sizeof(IPV4_HDR)+sizeof(TCP_HDR) + payload, 0, (SOCKADDR *)&dest, sizeof(dest));
        if (result <= 0){
            printf("Couldn't sent packet %d.", WSAGetLastError());
            break;
        }
        i++;
    }
}
