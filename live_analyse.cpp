#include "live_analyse.h"
#include <sys/socket.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <paquet.h>
#include <cstdio>
#include <mainwindow.h>
#include <QDebug>
#include <unistd.h>


live_analyse::live_analyse(QObject *parent) :
    QObject(parent)
{
    window = (MainWindow*)parent;
    _abort = false;
    _interrupt = false;
}

void live_analyse::requestPaquet()
{
    //qDebug()<<"Request worker Method"<<method<<"in Thread "<<thread()->currentThreadId();
    QMutexLocker locker(&mutex);
    _interrupt = true;
    //_method = method;
    condition.wakeOne();
}

void live_analyse::run()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
    struct sockaddr_in source,dest;
    int sock_raw;
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    int nbyt;

    printf("try socket\n");
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
     printf("socket %d\n", sock_raw);
       if(sock_raw < 0)
       {
           printf("Socket Error\n");
           perror("The following error occurred");
           //return ;
       }

       while(1)
       {
           qDebug("while ");
           printf("while \n");
           mutex.lock();
                   if (!_interrupt && !_abort) {
                       condition.wait(&mutex);
                   }
                   _interrupt = false;
                   qDebug("whil2 ");
                   printf("whil2 \n");
                   if (_abort) {
                       qDebug() <<"Aborting worker mainLoop in Thread "<<thread()->currentThreadId();
                       mutex.unlock();
                       close(sock_raw);
                       emit finished();
                       return;
                   }
                   qDebug("whil3 ");
                   printf("whil2 \n");

                   //Method method = _method;
                   mutex.unlock();
                    if(sock_raw < 0)
                        continue;
           saddr_size = sizeof saddr;
           //Receive a packet
           qDebug("while 1");
           printf("while 1\n");
           data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
           if(data_size <0 )
           {
               printf("Recvfrom error , failed to get packets\n");
               return ;
           }
           //Now process the packet
           paquet tmp = paquet(buffer, data_size);
           window->model.packets.push_back(tmp);
           window->refreshtableWidget();
        //   ref ->push_back(tmp);
//           ProcessPacket(buffer , data_size);
       }
//       }
}

void live_analyse::abort()
{
    QMutexLocker locker(&mutex);
    _abort = true;
    condition.wakeOne();
}
