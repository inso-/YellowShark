#include "pcap_analyse.h"
#include <netdb.h>
#include <QDebug>
#include <QThread>

struct pcap_pkthdr pcap_analyse::header;
//unsigned int pcap_analyse::pkt_counter = 0;
//unsigned long pcap_analyse::byte_counter = 0;
//unsigned long pcap_analyse::cur_counter = 0;
//unsigned long pcap_analyse::max_volume = 0;
//unsigned long pcap_analyse::current_ts = 0;
//char pcap_analyse::errbuf[PCAP_ERRBUF_SIZE];
//const u_char *pcap_analyse::packet;
pcap_t *pcap_analyse::handle;

pcap_analyse::pcap_analyse(QObject *parent) :
    QObject(parent)
  {
    window = (MainWindow*)parent;
    _abort = false;
    _interrupt = false;
}

//pcap_analyse::pcap_analyse(QObject *parent) :
//    QObject(parent)
//{
//    handle = pcap_open_offline(filename.toLatin1(), errbuf);   //call pcap library function


//   if (this->handle == NULL) {
//       qDebug("fail open file");
//       return;
//      }

//   return;
//}

void pcap_analyse::requestPaquet(QString filename)
{
    handle = pcap_open_offline(filename.toLatin1(), errbuf);   //call pcap library function


   if (this->handle == NULL) {
       qDebug("fail open file");
       return;
      }

    //qDebug()<<"Request worker Method"<<method<<"in Thread "<<thread()->currentThreadId();
    QMutexLocker locker(&mutex);
    _interrupt = true;
    //_method = method;
    condition.wakeOne();
}


void pcap_analyse::run()
{
    if(handle)
    {
        while (packet = pcap_next(handle,&pcap_analyse::header)) {
            mutex.lock();
                    if (!_interrupt && !_abort) {
                        condition.wait(&mutex);
                    }
                    if (_abort) {
                        qDebug() <<"Aborting worker mainLoop in Thread "<<thread()->currentThreadId();
                        mutex.unlock();
                         pcap_close(handle);
                        emit finished();
                        return;
                    }
                     mutex.unlock();
            qDebug("%s\n", "TEST");
            //Paquet
             // header contains information about the packet (e.g. timestamp)
            QDateTime timestamp;
            timestamp.setTime_t(header.ts.tv_sec);
//            tmp->date = timestamp;
            qDebug(timestamp.toString().toLatin1());
             u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data

            // paquet *tmp = new paquet(pkt_ptr, header);
             emit tvalueChanged(pkt_ptr, header);
//             tmp->pkt_ptr = pkt_ptr;
//             struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure

//             int packet_length = ntohs(ip_hdr->ip_len);

//             qDebug("Type : %d",  ip_hdr->ip_tos);
//             //check to see if the next second has started, for statistics purposes
//             if (current_ts == 0) {  //this takes care of the very first packet seen
//                current_ts = header.ts.tv_sec;
//             } else if (header.ts.tv_sec > current_ts) {
//                qDebug("%d KBps\n", cur_counter/1000); //print
//                cur_counter = 0; //reset counters
//                current_ts = header.ts.tv_sec; //update time interval
//             }

//             cur_counter += packet_length;
//             byte_counter += packet_length; //byte counter update
//             pkt_counter++; //increment number of packets seen
//             paquets.push_back(*tmp);

           } //end internal loop for reading packets (all in one file)

           pcap_close(handle);
         //  this->abort();
    }

    emit finished();

    //return paquets;
}

//void pcap_analyse::setPaquets(const std::vector<paquet> &value)
//{
//    paquets = value;
//}

void pcap_analyse::abort()
{
    QMutexLocker locker(&mutex);
    _abort = true;
    condition.wakeOne();
}

