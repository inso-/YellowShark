#ifndef PCAP_ANALYSE_H
#define PCAP_ANALYSE_H

#include <vector>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <QString>
#include <QDateTime>
#include "paquet.h"

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)




class pcap_analyse
{
    static struct pcap_pkthdr header;
    static unsigned int pkt_counter;
    static unsigned long byte_counter;
    static unsigned long cur_counter;
    static unsigned long max_volume;
    static unsigned long current_ts;
    static char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
// The header that pcap gives us
    static const u_char *packet; // The actual packet
    static pcap_t *handle;
public:
    pcap_analyse(QString filename);
    std::vector<paquet> getPaquets() const;
    void setPaquets(const std::vector<paquet> &value);

private:
    std::vector<paquet> paquets;
    QString fileName;

};


#endif // PCAP_ANALYSE_H
