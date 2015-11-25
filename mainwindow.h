#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <live_analyse.h>
#include <QMainWindow>
#include <QAbstractTableModel>
#include <stdexcept>
#include <QItemSelection>
#include <sendpacketwindow.h>
#include <filterwindow.h>
#include <pcap_analyse.h>
#include <QThread>
#include "filterwindow.h"
#include "paquet.h"

class TestModel : public QAbstractTableModel
{
public slots:
    //void selectionChangedSlot(const QItemSelection &newSelection,const QItemSelection &oldSelection);
public:
    std::vector<paquet> packets;

    void clear()
    {
        packets.clear();
    }

    int addPaquet(paquet packet)
    {
        emit beginInsertRows(QModelIndex(), packets.size(), packets.size());
        packets.push_back(packet);
        emit endInsertRows();
        //QModelIndex top = createIndex(packets.size(), );


      //  emit dataChanged();
      //  qDebug("%d",packets.size());
//        return packets.size();
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const
    {
      //  qDebug("%d",packets.size());
        return packets.size();
    }
    int columnCount(const QModelIndex &parent = QModelIndex()) const
    {
        return 8;
    }
    QVariant data(const QModelIndex &index, int role) const
    {
        switch (role)
        {
        case Qt::DisplayRole:
        {
            try{
            switch (index.column())
            {
            case 0:
                return index.row();
            case 1:
                return packets.at(index.row()).date.toString("dd/MM/yyyy hh:mm:ss:zzz ");
            case 2:
                return packets.at(index.row()).type.c_str();
            case 3:
                return packets.at(index.row()).source.c_str();
            case 4:
                return packets.at(index.row()).sourcePort.c_str();
            case 5:
                return packets.at(index.row()).destination.c_str();
            case 6:
                return packets.at(index.row()).destinationPort.c_str();
            case 7:
                return (int)(packets.at(index.row()).size);
            default:
                break;
            }
            }
            catch (const std::out_of_range& e) {
                return 0;
            }
        }
        }
        return QVariant();
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const
    {
        if (role == Qt::DisplayRole)
        {
            if (orientation == Qt::Horizontal) {
                switch (section)
                {
                case 0:
                    return QString("Numbers");
                case 1:
                    return QString("Date");
                case 2:
                    return QString("Type");
                case 3:
                    return QString("Source");
                case 4:
                    return QString("Source Port");
                case 5:
                    return QString("Destination");
                case 6:
                    return QString("Destination Port");
                case 7:
                    return QString("Length");
                }
              if (orientation == Qt::Vertical)
                  return section;
            }
        }
        return QVariant();
    }
};

    Q_DECLARE_METATYPE(paquet);

namespace Ui {
class MainWindow;
}

//class live_analyse;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    TestModel model;
    void refreshtableWidget();
    QThread *thread;
private slots:
    void on_actionOpen_triggered();
    void on_tableWidget_activated(const QModelIndex &index);
    void on_actionSend_a_crafted_packet_triggered();


    void on_actionFilter_Capture_triggered();
    void on_actionClear_Capture_triggered();
    void on_actionStart_Capture_triggered();

    void on_actionSave_triggered();

    void on_actionModify_and_Send_Selected_Packet_triggered();

public slots:
     void tableWidgetSelectionModel_currentRowChanged(QModelIndex newSelection,QModelIndex oldSelection);
     void testChanged(unsigned char *, int);
     void pcapChanged(unsigned char *buffer,  pcap_pkthdr header);
     void filterChanged(filter fil);
     void threadFinished();
private:
    int run_pcap;
    int run_live;
    int selected;
    pcap_analyse *parse;
    live_analyse *live;
    Ui::MainWindow *ui;
    SendPacketWindow *sendwindow;
    FilterWindow *filterwindow;
    filter filter;

//public:
    //void getDataFromFile();
    void clear();
    void addPaquet(paquet &tmp);
};

#endif // MAINWINDOW_H
