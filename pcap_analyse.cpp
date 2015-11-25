#include "pcap_analyse.h"
#include <netdb.h>
#include <QDebug>
#include <QThread>

struct pcap_pkthdr pcap_analyse::header;
pcap_t *pcap_analyse::handle;

pcap_analyse::pcap_analyse(QObject *parent) :
    QObject(parent)
  {
    window = (MainWindow*)parent;
    _abort = false;
    _interrupt = false;
}

void pcap_analyse::requestPaquet(QString filename)
{
  handle = pcap_open_offline(filename.toLatin1(), errbuf);   //call pcap library function
  if (this->handle == NULL) {
    qDebug("fail open file");
    return;
  }
    QMutexLocker locker(&mutex);
    _interrupt = true;
    condition.wakeOne();
}


void pcap_analyse::run()
{
  u_char * data;
  struct pcap_pkthdr *pkt_hdr;
  if(handle)
    {
      while (int returnValue = pcap_next_ex(handle, &pkt_hdr, const_cast<const u_char**>(&data)) >= 0) {
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
	QDateTime timestamp;
	qDebug(timestamp.toString().toLatin1());
    emit tvalueChanged(const_cast<uchar *> (data), *pkt_hdr);
  //  pkt_hdr = malloc(sizeof(struct_pkthdr));
      } //end internal loop for reading packets (all in one file)
      pcap_close(handle);
    }
  emit finished();
}

void pcap_analyse::abort()
{
    QMutexLocker locker(&mutex);
    _abort = true;
    condition.wakeOne();
}

