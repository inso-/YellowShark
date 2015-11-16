#ifndef PAQUET_H
#define PAQUET_H
#include <netdb.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <QString>
#include <string>
#include <QDate>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
//#include<netinet/ipv6.h>

struct ipv6
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_TYPE_IPV6 (0x86DD)



class paquet
{
public:
    paquet(u_char *pkt, pcap_pkthdr header);
    paquet(u_char *pkt, int size);
    paquet(std::string type,
                   std::string source,
                   std::string sourceport,
                   std::string destination,
                   std::string destinationport,
                   std::string data);

    QDateTime   date;
    std::string type;
    std::string source;
    std::string destination;
    std::string sourcePort;
    std::string destinationPort;
    std::string payload;
    int ether_offset;
    uchar      *pkt_ptr;
    #ifdef __APPLE__
    struct ip *ip_hdr;
    #else
    struct iphdr *ip_hdr;
    #endif
    struct ipv6 *ipv6_hdr;
    struct tcphdr *tcp_hdr;     // tcp header struct
    struct udphdr *udp_hdr;     // udp header struct
    struct sockaddr_in sin;
    struct pseudo_header psh;
    char datagram[4096];
    char *pseudogram;
    char *data;
    unsigned long size_ip;
    unsigned long size_ucp;
    unsigned long size_tcp;
    int size_payload;
    unsigned long size;
    void send();


private:
    void parse_ether_type();
    void parse_ip_header();
    void parse_ipv6_header();
    void parse_tcp_header();
    void parse_udp_header();
    unsigned short csum(unsigned short *ptr,int nbytes);
    void build_ip_header();
    void build_tcp_header();
    void build_data_part();
    void get_protocol(int proto);
    void init(u_char* pkt, int size);
};

#endif // PAQUET_H
