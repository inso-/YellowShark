#ifndef TOOLS_H
#define TOOLS_H

#include <QString>
#include <iomanip>
#include <sstream>



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

//class tools
//{
//public:
//    tools();

//signals:

//public slots:
//};

#endif // TOOLS_H
