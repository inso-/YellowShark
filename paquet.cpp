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

  paquet::paquet()
  {
    //  QDateTime timestamp = QDateTime::currentDateTime();
    //  this->date = timestamp;

    //  this->init(pkt, size);
  }

paquet::paquet(u_char *pkt, int size)
{
    QDateTime timestamp = QDateTime::currentDateTime();
    this->date = timestamp;

    this->init(pkt, size);
}

paquet::paquet(std::string type, std::string source,std::string sourceport, std::string destination,std::string destinationport, std::string data)
{
    this->source = source;
    this->type = type;
    this->destination = destination;
    this->destinationPort = destinationport;
    this->sourcePort = sourceport;
    this->payload = data;
    this->build_data_part();
    this->build_ip_header();
    this->build_tcp_header();
}

unsigned short paquet::csum(unsigned short *ptr,int nbytes)
{
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


void paquet::build_ip_header()
{
      #ifdef __APPLE__

    ip_hdr = (struct ip*) datagram;
    //Fill in the IP Header
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
  //  ip_hdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr) + strlen(data);
  //  ip_hdr->ip_id = htonl (54321); //Id of this packet
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
//        if (TCP)
    ip_hdr->ip_p = IPPROTO_TCP;
    //else if (UDP)
    //iph->protocol = IPPROTO_UDP;;
    //else if (icm)
    //iph->protocol = IPPROTO_ICMP;;
    ip_hdr->ip_sum = 0;      //Set to 0 before calculating checksum
   // ip_hdr->ip_src = inet_addr ( this->source.c_str() );    //Spoof the source ip address
   // ip_hdr->ip_dst = sin.sin_addr.s_addr;
    //Ip checksum
   // ip_hdr->ip_sum = this->csum ((unsigned short *) datagram, iph->tot_len);
#eldef __WIN32
#else
     ip_hdr = (struct iphdr *) datagram;
    //ip_hdr = (iphdr*)malloc(sizeof(iphdr));
    ip_hdr->ihl = 5;
        ip_hdr->version = 4;
        ip_hdr->tos = 0;
        ip_hdr->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
        ip_hdr->id = htonl (54321); //Id of this packet
        ip_hdr->frag_off = 0;
        ip_hdr->ttl = 255;
        ip_hdr->protocol = IPPROTO_TCP;
        ip_hdr->check = 0;      //Set to 0 before calculating checksum
        ip_hdr->saddr = inet_addr ( this->source.c_str() );    //Spoof the source ip address
        ip_hdr->daddr = sin.sin_addr.s_addr;
#endif

}

void paquet::build_tcp_header()
{
  //tcp_hdr = (tcphdr*)malloc(sizeof(tcphdr));
  #ifdef __APPLE__
    tcp_hdr = (struct tcphdr *) (datagram + sizeof (struct ip));
    tcp_hdr->th_sport = htons (1234);
    tcp_hdr->th_dport = htons (80);
    tcp_hdr->th_seq = 0;
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5;  //tcp header size
    //tcp_hdr-> fin=0;
    //tcp_hdr->th_ syn=1;
    //tcp_hdr-> rst=0;
    //tcp_hdr->th_ psh=0;
    //tcp_hdr->ack=0;
    tcp_hdr->th_urp =0;
    tcp_hdr->th_win = htons (5840); /* maximum allowed window size */
    tcp_hdr->th_sum = 0; //leave checksum 0 now, filled later by pseudo header
    //tcp_hdr-> urg_ptr = 0;
    psh.source_address = inet_addr( source.c_str() );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcp_hdr , sizeof(struct tcphdr) + strlen(data));
    tcp_hdr->th_sum = this->csum( (unsigned short*) pseudogram , psize);
  #eldef __WIN32
  #else
    tcp_hdr = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    tcp_hdr->source = htons (1234);
    tcp_hdr->dest = htons (80);
    tcp_hdr->seq = 0;
    tcp_hdr->ack_seq = 0;
    tcp_hdr->doff = 5;  //tcp header size
    tcp_hdr->fin=0;
    tcp_hdr->syn=1;
    tcp_hdr->rst=0;
    tcp_hdr->psh=0;
    tcp_hdr->ack=0;
    tcp_hdr->urg=0;
    tcp_hdr->window = htons (5840); /* maximum allowed window size */
    tcp_hdr->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcp_hdr->urg_ptr = 0;

    psh.source_address = inet_addr( source.c_str() );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcp_hdr , sizeof(struct tcphdr) + strlen(data));

    tcp_hdr->check = csum( (unsigned short*) pseudogram , psize);
 #endif


}

void paquet::build_data_part()
{
    //Data part
    memset (datagram, 0, 4096);
    data = datagram + sizeof(struct ip) + sizeof(struct tcphdr);
    strcpy(data , payload.c_str());

    //some address resolution
   // strcpy(source_ip , "192.168.1.2");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr (destination.c_str());
}

void paquet::send()
{
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

        if(s == -1)
        {
            //socket creation failed, may be because of non-root privileges
            perror("Failed to create socket");
            exit(1);
        }

    int one = 1;
    const int *val = &one;

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    //loop if you want to flood :)
    //while (1)
    //{
        //Send the packet
     #ifdef __APPLE__
    if (sendto (s, datagram, ip_hdr->ip_tos,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    #eldef __WIN32
    #else
        if (sendto (s, datagram, ip_hdr->tos,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
     #endif
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
             #ifdef __APPLE__
            printf ("Packet Send. Length : %d \n" , ip_hdr->ip_tos);
#eldef __WIN32
#else
            printf ("Packet Send. Length : %d \n" , ip_hdr->tos);
             #endif
        }
    //}
}

paquet::paquet(u_char *pkt, pcap_pkthdr header)
{
    QDateTime timestamp;

    timestamp.setTime_t(header.ts.tv_sec);
    timestamp.setTime(timestamp.time().addMSecs((int)(header.ts.tv_usec / 1000.0)));
    this->date = timestamp;

    this->init(pkt, header.len);
}

void paquet::init(u_char* pkt, int size)
{
    pkt_ptr = pkt;
    this->size = size;
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
    else if (this->type == "icmp")
         this->parse_icmp_header();
    else {
        this->sourcePort = "0";
        this->destinationPort = "0";
    }

    qDebug("size header pcap %d", size);
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
    this->size_ip = packet_length;
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
    ip_hdr = (struct iphdr *)pkt_ptr; //point to an IP header structure

#ifdef __APPLE__
    int packet_length = ntohs(ip_hdr->ip_len);
    this->size_ip = packet_length;
    this->source = inet_ntoa(ip_hdr->ip_src);
    this->destination = inet_ntoa(ip_hdr->ip_dst);
    this->get_protocol(ip_hdr->ip_p);
    qDebug("size header ip %d", this->size);
#eldef __WIN32
#else
    int packet_length = ntohs(ip_hdr->tot_len);
    this->size_ip = packet_length;
    struct sockaddr_in ip_addr;
    ip_addr.sin_addr.s_addr = ip_hdr->saddr;


    this->source = inet_ntoa( ip_addr.sin_addr);
    ip_addr.sin_addr.s_addr = ip_hdr->daddr;
     this->destination = inet_ntoa( ip_addr.sin_addr);
 //       ip_addr.s_addr = ip_hdr->daddr;
  //  this->destination = inet_ntoa(ip_addr);
    this->get_protocol(ip_hdr->protocol);
    qDebug("size header ip %d", this->size);
#endif

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

#ifdef __APPLE__
    int iphdrlen = ip_hdr->ip_hl * 4;

 tcp_hdr = (struct tcphdr*)(pkt_ptr + iphdrlen);
    qDebug("   Src port: %d\n", ntohs(tcp_hdr->th_sport));
    qDebug("   Dst port: %d\n", ntohs(tcp_hdr->th_dport));
    this->sourcePort = NumberToString(ntohs(tcp_hdr->th_sport));
    this->destinationPort = NumberToString(ntohs(tcp_hdr->th_dport));
#eldef __WIN32
#else
    int iphdrlen = ip_hdr->ihl * 4;

    tcp_hdr = (struct tcphdr*)(pkt_ptr + iphdrlen);

    qDebug("   Src port: %d\n", ntohs(tcp_hdr->source));
    qDebug("   Dst port: %d\n", ntohs(tcp_hdr->dest));
    this->sourcePort = NumberToString(ntohs(tcp_hdr->dest));
    this->destinationPort = NumberToString(ntohs(tcp_hdr->source));
#endif


       //struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
}

void paquet::parse_udp_header()
{
    unsigned short iphdrlen;


#ifdef __APPLE__
    iphdrlen = ip_hdr->ip_hl * 4;

    udp_hdr = (struct udphdr*)(pkt_ptr + iphdrlen);
    this->sourcePort = NumberToString(ntohs(udp_hdr->uh_sport));
    this->destinationPort = NumberToString(ntohs(udp_hdr->uh_dport));
#eldef __WIN32
#else
    iphdrlen = ip_hdr->ihl * 4;

    udp_hdr = (struct udphdr*)(pkt_ptr + iphdrlen);
    this->sourcePort = NumberToString(ntohs(udp_hdr->source));
    this->destinationPort = NumberToString(ntohs(udp_hdr->dest));
#endif
}
void paquet::parse_icmp_header()
{

    unsigned short iphdrlen;


#ifdef __APPLE__
    iphdrlen = ip_hdr->ip_hl * 4;

    icmp_hdr = (struct icmphdr*)(pkt_ptr + iphdrlen);
 //   this->sourcePort = NumberToString(ntohs(udp_hdr->uh_sport));
 //   this->destinationPort = NumberToString(ntohs(udp_hdr->uh_dport));
#eldef __WIN32
#else
    iphdrlen = ip_hdr->ihl * 4;

    icmp_hdr = (struct icmphdr*)(pkt_ptr + iphdrlen);
  //  this->sourcePort = NumberToString(ntohs(icmp_hdr->));
  //  this->destinationPort = NumberToString(ntohs(icmp_hdr->dest));
#endif
     this->sourcePort = "no";
     this->destinationPort = "no";
}


