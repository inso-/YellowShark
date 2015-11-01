#include <ostream>
#include <sstream>
#include <tools.h>
#include "paquet.h"


template <typename T>
  std::string NumberToString ( T Number )
  {
     std::ostringstream ss;
     ss << Number;
     return ss.str();
  }

paquet::paquet(u_char *pkt, pcap_pkthdr header)
{
    pkt_ptr = pkt;
    this->parse_ether_type();
     if (this->ether_offset == -1)
         return;
    if (this->ether_offset == 0)
        this->parse_ipv6_header();
    else
        this->parse_ip_header();
    if (this->type == "tcp")
        this->parse_tcp_header();
    else if (this->type == "udp")
         this->parse_udp_header();
    else {
        this->sourcePort = "0";
        this->destinationPort = "0";
    }
    QDateTime timestamp;
    timestamp.setTime_t(header.ts.tv_sec);
    this->date = timestamp;
}

void paquet::parse_ether_type()
{
    int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];

    if (ether_type == ETHER_TYPE_IP) //most common
      ether_offset = 14;
    else if (ether_type == ETHER_TYPE_8021Q) //my traces have this
       ether_offset = 18;
    else if (ether_type == ETHER_TYPE_IPV6) // ip v6
        ether_offset = 0;
    else
    {
        ether_offset = -1;
       fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);
    }
}

void paquet::parse_ipv6_header()
{
    pkt_ptr += ether_offset;  //skip past the Ethernet II header
    ipv6_hdr = (struct ipv6 *)pkt_ptr;
    char straddr[INET6_ADDRSTRLEN];

    int packet_length = ntohs(ipv6_hdr->length);
    this->size = packet_length;
    inet_ntop(AF_INET6, &ipv6_hdr->src, straddr,
                                 sizeof(straddr));
    this->source = straddr;
    inet_ntop(AF_INET6, &ipv6_hdr->dst, straddr,
                                 sizeof(straddr));
    this->destination = straddr;
    qDebug("ipv6 proto : %d", ipv6_hdr->next_header);
    this->get_protocol(ipv6_hdr->next_header);
}

void paquet::get_protocol(int proto)
{
    struct protoent *test;

    test =      getprotobynumber(proto);
    if (test)
       this->type = test->p_name;
    else{
        qDebug("alert proto %d not found", proto);
    switch (proto)
    {
    case 142:
    {
        this->type = "rohc";
        break;
    }
    default:
        this->type = "unknow(" + NumberToString((int)proto) + ")";
        qDebug("alert proto %d not found", proto);
    }
    }
}

void paquet::parse_ip_header()
{
    //parse the IP header
    pkt_ptr += ether_offset;  //skip past the Ethernet II header
    ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure

    int packet_length = ntohs(ip_hdr->ip_len);
    this->size = packet_length;
    this->source = inet_ntoa(ip_hdr->ip_src);
    this->destination = inet_ntoa(ip_hdr->ip_dst);
    this->get_protocol(ip_hdr->ip_p);
}

void paquet::parse_tcp_header()
{
//    tcp = (struct tcp_hdr*)(packet + ether_offset + ip_hdr->ip_len);
//        //size_tcp = TH_OFF(tcp)*4;
//        //if (size_tcp < 20) {
//        //    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
//        //    return;
//        //}

//
       int iphdrlen = ip_hdr->ip_hl * 4;

    tcp_hdr = (struct tcphdr*)(pkt_ptr + iphdrlen);
    qDebug("   Src port: %d\n", ntohs(tcp_hdr->th_sport));
    qDebug("   Dst port: %d\n", ntohs(tcp_hdr->th_dport));
    this->sourcePort = NumberToString(ntohs(tcp_hdr->th_sport));
    this->destinationPort = NumberToString(ntohs(tcp_hdr->th_dport));

       //struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
}

void paquet::parse_udp_header()
{
    unsigned short iphdrlen;

    iphdrlen = ip_hdr->ip_hl * 4;

    udp_hdr = (struct udphdr*)(pkt_ptr + iphdrlen);
    this->sourcePort = NumberToString(ntohs(udp_hdr->uh_sport));
    this->destinationPort = NumberToString(ntohs(udp_hdr->uh_dport));

}


