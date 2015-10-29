#include <string>
#include <QDate>

#ifndef PAQUET_H
#define PAQUET_H


class paquet
{
public:
    paquet();

    QDateTime   date;
    std::string type;
    std::string source;
    std::string destination;
    uchar      *pkt_ptr;
    unsigned long size;


private:


};

#endif // PAQUET_H
