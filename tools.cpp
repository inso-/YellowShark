#include "tools.h"

//tools::tools()
//{

//}


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
