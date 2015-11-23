#include "tools.h"




    QString FormatData(unsigned char* data , int Size)
    {
        QString res;

        for(int i=0 ; i < Size ; i++)
        {
            if( i!=0 && i%16==0)   //if one line of hex printing is complete...
            {
                //res += "         ";
                for(int j=i-16 ; j<i ; j++)
                {
                    if(data[j]>=32 && data[j]<=128)
                        res += (unsigned char)data[j]; //if its a number or alphabet

                    else res += "."; //otherwise print a dot
                }

               res += "\n";
    //            fprintf(logfile,"\n");
            }
            if( i==Size-1)  //print the last spaces
            {
                for(int j=0;j<15-i%16;j++)
                    res += "   "; //extra spaces

                res += "         ";

                for(int j=i-i%16 ; j<=i ; j++)
                {
                    if(data[j]>=32 && data[j]<=128)
                        res += (unsigned char)data[j];
                    else
                        res += ".";
                }
                res += "\n";
            }
        }
        return res;
    }

    QString FormatHexData (unsigned char* data , int Size)
    {
        QString res;

        for(int i=0 ; i < Size ; i++)
        {
               if(i%16==0)
                   res += "\n";
               res += " ";
               res += QString::fromStdString( NumberToHexString((unsigned int)data[i]));

        }
        return res;
    }
    QString FormatHeaderData(paquet *pkt)
    {
        QString data;
        if (pkt->ether_offset == 0)
            data += FormatIpv6Header(pkt);
        else if (pkt->ether_offset == 14 || pkt->ether_offset == 18)
            data += FormatIpHeader(pkt);
        else if (pkt->ether_offset == -2)
            data += FormatArpHeader(pkt);

        if (pkt->type == "tcp")
            data += FormatTcpHeader(pkt);
        else if (pkt->type == "udp")
            data += FormatUdpHeader(pkt);
        else if (pkt->type == "icmp")
            data += FormatIcmpHeader(pkt);

        return data;
    }

    QString FormatIpHeader(paquet *pkt)
    {
        QString data;

        data += "IP HEADER\n";
        data += QString::fromLatin1("|-IP Version : ") +
                QString::number((unsigned int)pkt->ip_hdr->version)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP Header Lenght DWORDS : ") +
                QString::number((unsigned int)pkt->ip_hdr->ihl)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP Header Lenght Bytes : ") +
                QString::number((unsigned int)pkt->ip_hdr->ihl * 4)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP Type of Service : ") +
                QString::number((unsigned int)pkt->ip_hdr->tos)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP Total lenght : ") +
                QString::number(ntohs(pkt->ip_hdr->tot_len))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP identification : ") +
                QString::number(ntohs(pkt->ip_hdr->id))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP Time To Live : ") +
                QString::number((unsigned int)pkt->ip_hdr->ttl)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP protocol : ") +
                QString::number((unsigned int)pkt->ip_hdr->protocol)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP checksum : ") +
                QString::number(ntohs(pkt->ip_hdr->check))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP source : ") +
                QString::fromStdString(pkt->source) +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-IP destination : ") +
                QString::fromStdString(pkt->destination) +
                QString::fromLatin1("\n");

        return data;
    }
    QString FormatIpv6Header(paquet *pkt)
    {
        QString data;
        return data;
    }
    QString FormatArpHeader(paquet *pkt)
    {
        QString data;
        return data;
    }
    QString FormatTcpHeader(paquet *pkt)
    {
        QString data;

        data += "TCP HEADER\n";
        data += QString::fromLatin1("|-TCP Source Port : ") +
                QString::fromStdString(pkt->sourcePort) +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Destination Port : ") +
                QString::fromStdString(pkt->destinationPort) +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Sequence Number : ") +
                QString::number(ntohl(pkt->tcp_hdr->seq))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Acknowledge Number : ") +
                QString::number(ntohl(pkt->tcp_hdr->ack_seq))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Urgent Flag : ") +
                QString::number((unsigned int)pkt->tcp_hdr->urg)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Acknowledgment Flag : ") +
                QString::number(ntohs(pkt->tcp_hdr->ack))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Push Flag : ") +
                QString::number(ntohs(pkt->tcp_hdr->psh))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Reset Flag : ") +
                QString::number(ntohs(pkt->tcp_hdr->rst))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Synchronize Flag : ") +
                QString::number(ntohs(pkt->tcp_hdr->syn))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Finish Flag : ") +
                QString::number(ntohs(pkt->tcp_hdr->fin))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Window : ") +
                QString::number(ntohs(pkt->tcp_hdr->window))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Checksum : ") +
                QString::number(ntohs(pkt->tcp_hdr->check))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-TCP Urgent pointer : ") +
                QString::number(ntohs(pkt->tcp_hdr->urg_ptr))  +
                QString::fromLatin1("\n");
        return data;
    }
    QString FormatUdpHeader(paquet *pkt)
    {
        QString data;

        data += "UDP HEADER\n";
        data += QString::fromLatin1("|-UDP Source Port : ") +
                 QString::fromStdString(pkt->sourcePort) +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-UDP Destination Port : ") +
                QString::fromStdString(pkt->destinationPort) +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-UDP Lenght : ") +
                QString::number(ntohs(pkt->udp_hdr->len))  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-UDP Checksum : ") +
                QString::number(ntohs(pkt->udp_hdr->check))  +
                QString::fromLatin1("\n");

        return data;
    }
    QString FormatIcmpHeader(paquet *pkt)
    {
        QString data;

        data += "ICMP HEADER\n";
        data += QString::fromLatin1("|-ICMP Type : ") +
                QString::number((unsigned int)pkt->icmp_hdr->type)  +
                QString::fromLatin1("\n");
        if (pkt->icmp_hdr->type == ICMP_ECHO)
            data += QString::fromLatin1("   (ICMP Echo)\n");
        else if (pkt->icmp_hdr->type == ICMP_ECHOREPLY)
            data += QString::fromLatin1("   (ICMP Echo reply)\n");
        else if (pkt->icmp_hdr->type == ICMP_TIME_EXCEEDED)
            data += QString::fromLatin1("   (ICMP Expired)\n");
        data += QString::fromLatin1("|-ICMP Code : ") +
                QString::number((unsigned int)pkt->icmp_hdr->code)  +
                QString::fromLatin1("\n");
        data += QString::fromLatin1("|-ICMP Checksum : ") +
                QString::number(ntohs(pkt->icmp_hdr->checksum))  +
                QString::fromLatin1("\n");
        return data;
    }
