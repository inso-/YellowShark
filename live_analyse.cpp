#include "live_analyse.h"
#include <sys/socket.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <paquet.h>
#include <cstdio>
#include <mainwindow.h>
#include <QDebug>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <fcntl.h>


live_analyse::live_analyse(QObject *parent) :
    QObject(parent)
{
    window = (MainWindow*)parent;
    _abort = false;
    _interrupt = false;
   // condition.wakeAll();
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
    fd_set toRead;
    int sel;
    struct timeval waitd;

    waitd.tv_sec = 1;

    printf("try socket\n");
    sock_raw = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));
     printf("socket %d\n", sock_raw);
       if(sock_raw < 0)
       {
           printf("Socket Error\n");
           perror("The following error occurred");
           //window->run_live = 0;
           emit finished();
           return ;
       }
      int flags;

      flags = fcntl(sock_raw, F_GETFL, 0);
      if (flags == -1) {
          close(sock_raw);
          emit finished();
         return; }
      fcntl(sock_raw, F_SETFL, flags | O_NONBLOCK);
       while(1)
       {
           FD_ZERO(&toRead);
           FD_SET(sock_raw, &toRead);
       //    qDebug("while ");
       //    printf("while \n");
           mutex.lock();
                   if (!_interrupt && !_abort) {
                       condition.wait(&mutex);
                   }
                  // _interrupt = false;
                   //qDebug("whil2 ");
           //        printf("whil2 \n");
                   if (_abort) {
                       qDebug() <<"Aborting worker mainLoop in Thread "<<thread()->currentThreadId();
                       mutex.unlock();
                       close(sock_raw);
                       emit finished();
                       return;
                   }
                   //qDebug("whil3 ");
               //    printf("whil3 \n");

                   //Method method = _method;
                   mutex.unlock();
                    if(sock_raw < 0)
                        continue;
           saddr_size = sizeof saddr;
           //Receive a packet
 //          qDebug("while 1");
         //  printf("while 4\n");

           sel = select(sock_raw + 1, &toRead, (fd_set*)0,(fd_set*)0, &waitd);
           if (sel < 0)
               continue;
           if (FD_ISSET(sock_raw, &toRead))
              {
                printf("something to read\n");
               FD_CLR(sock_raw, &toRead);
           data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
           if(data_size <0 )
           {
               printf("Recvfrom error , failed to get packets\n");
               return ;
           }
           //Now process the packet
           paquet tmp = paquet(buffer, data_size);
           emit tvalueChanged(buffer, data_size);
       //    window->model.packets.push_back(tmp);
        //   window->refreshtableWidget();
        //   ref ->push_back(tmp);
//           ProcessPacket(buffer , data_size);
       }
      }
       close(sock_raw);
       emit finished();
}

void live_analyse::abort()
{
    QMutexLocker locker(&mutex);
    _abort = true;
    condition.wakeOne();
}
