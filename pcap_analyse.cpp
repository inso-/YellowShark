#include "pcap_analyse.h"
#include <netdb.h>

struct pcap_pkthdr pcap_analyse::header;
unsigned int pcap_analyse::pkt_counter = 0;
unsigned long pcap_analyse::byte_counter = 0;
unsigned long pcap_analyse::cur_counter = 0;
unsigned long pcap_analyse::max_volume = 0;
unsigned long pcap_analyse::current_ts = 0;
char pcap_analyse::errbuf[PCAP_ERRBUF_SIZE];
const u_char *pcap_analyse::packet;
pcap_t *pcap_analyse::handle;

pcap_analyse::pcap_analyse(QString filename)
{
    handle = pcap_open_offline(filename.toLatin1(), errbuf);   //call pcap library function

   if (this->handle == NULL) {
       qDebug("fail open file");
       return;
      }
   return;
}



std::vector<paquet> pcap_analyse::getPaquets(void) const
{
    if(handle)
    {
        while (packet = pcap_next(handle,&header)) {
            qDebug("%s\n", "TEST");
            //Paquet
             // header contains information about the packet (e.g. timestamp)
            QDateTime timestamp;
            timestamp.setTime_t(header.ts.tv_sec);
//            tmp->date = timestamp;
            qDebug(timestamp.toString().toLatin1());
             u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data
             paquet *tmp = new paquet(pkt_ptr, header);
//            tmp->pkt_ptr = pkt_ptr;
             //parse the first (ethernet) header, grabbing the type field
//             int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
//             int ether_offset = 0;

//             if (ether_type == ETHER_TYPE_IP) //most common
//               ether_offset = 14;
//             else if (ether_type == ETHER_TYPE_8021Q) //my traces have this
//                ether_offset = 18;
//             else
//                fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);

//             //parse the IP header
//             pkt_ptr += ether_offset;  //skip past the Ethernet II header
//             struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure

//             int packet_length = ntohs(ip_hdr->ip_len);
//             tmp->size = packet_length;
//             tmp->source = inet_ntoa(ip_hdr->ip_src);
//             tmp->destination = inet_ntoa(ip_hdr->ip_dst);
//             struct protoent *test;

//             test =      getprotobynumber(ip_hdr->ip_p);
//             if (test)
//                tmp->type = test->p_name;
//             else{
//                 qDebug("alert proto %d not found", ip_hdr->ip_p);
//             switch (ip_hdr->ip_p)
//             {
//             case 142:
//             {
//                 tmp->type = "rohc";
//                 break;
//             }
//             default:
//                 tmp->type = "unknow(" + NumberToString((int)ip_hdr->ip_p) + ")";
//                 qDebug("alert proto %d not found", ip_hdr->ip_p);
//             }
//        }

             struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure

             int packet_length = ntohs(ip_hdr->ip_len);

//             qDebug("Type : %d",  ip_hdr->ip_tos);
             //check to see if the next second has started, for statistics purposes
             if (current_ts == 0) {  //this takes care of the very first packet seen
                current_ts = header.ts.tv_sec;
             } else if (header.ts.tv_sec > current_ts) {
                qDebug("%d KBps\n", cur_counter/1000); //print
                cur_counter = 0; //reset counters
                current_ts = header.ts.tv_sec; //update time interval
             }

             cur_counter += packet_length;
             byte_counter += packet_length; //byte counter update
             pkt_counter++; //increment number of packets seen
             paquets.push_back(*tmp);
           } //end internal loop for reading packets (all in one file)

           pcap_close(handle);
    }
    return paquets;
}

void pcap_analyse::setPaquets(const std::vector<paquet> &value)
{
    paquets = value;
}

