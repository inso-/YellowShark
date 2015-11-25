#ifndef TOOLS_H
#define TOOLS_H

#include <QString>
#include <iomanip>
#include <sstream>
#include "paquet.h"


  template <typename T>
    std::string NumberToHexString ( T Number )
    {
        std::stringstream stream;
          stream <<
                 std::setfill ('0') << std::setw(2)
                 << std::hex << Number;
          return stream.str();
    }


//template <typename T>
//  std::string NumberToString (T);

//template <typename T>
//    std::string NumberToHexString (T);

template <int>
        std::string NumberToHexString (int);

QString FormatData(unsigned char* data , int Size);
QString FormatHexData (unsigned char* data , int Size);
QString FormatHeaderData(paquet *pkt);
QString FormatIpHeader(paquet *pkt);
QString FormatIpv6Header(paquet *pkt);
QString FormatArpHeader(paquet *pkt);
QString FormatTcpHeader(paquet *pkt);
QString FormatUdpHeader(paquet *pkt);
QString FormatIcmpHeader(paquet *pkt);
//class tools
//{
//public:
//    tools();

//signals:

//public slots:
//};

#endif // TOOLS_H
