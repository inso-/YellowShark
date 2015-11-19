#ifndef PCAP_ANALYSE_H
#define PCAP_ANALYSE_H

//#include <vector>
//#include <pcap.h>
//#include <pcap/pcap.h>
//#include <stdlib.h>
//#include <netinet/ip.h>
//#include <arpa/inet.h>
//#include <QString>
//#include <QDateTime>
//#include <QWaitCondition>
//#include <QObject>
//#include <QMutex>
//#include <QDebug>
//#include <QTimer>
//#include <QThread>
//#include <QEventLoop>
#include <vector>
#include <paquet.h>
//#include <mainwindow.h>
#include <QEventLoop>
//#include <QThread>
//#include <QTimer>
#include <QWaitCondition>
#include <QObject>
#include <QMutex>
#include "paquet.h"

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)


class MainWindow;

class pcap_analyse : public QObject
{
        Q_OBJECT
  public:
    explicit pcap_analyse(QObject *parent = 0);

    void abort();
   // static struct pcap_pkthdr header;
    unsigned int pkt_counter;
    unsigned long byte_counter;
    unsigned long cur_counter;
    unsigned long max_volume;
    unsigned long current_ts;
//    const u_char *packet;
 //   pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
// The header that pcap gives us
    const u_char *packet; // The actual packet
    static pcap_t *handle;
    static struct pcap_pkthdr header;
    QWaitCondition condition;
    bool _abort;
    bool _interrupt;
    QMutex mutex;

    void requestPaquet(QString filename);
            MainWindow* window;

  //  pcap_analyse(QString filename, QObject *parent = 0);
  //  std::vector<paquet> getPaquets() const;
  //  void setPaquets(const std::vector<paquet> &value);


signals:
    void tvalueChanged(unsigned char *, pcap_pkthdr);
    void finished();

public slots:
    void run();

private:
   // mutable std::vector<paquet> paquets;
    QString fileName;

};


#endif // PCAP_ANALYSE_H
