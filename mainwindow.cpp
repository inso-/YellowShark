#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <stdio.h>
#include <QFileDialog>
#include <iostream>
#include <QDebug>
#include <QDateTime>
#include <paquet.h>
#include <QSortFilterProxyModel>
#include <QItemSelection>
#include <QString>
#include <sstream>
#include <iomanip>
#include <tools.h>
#include <future>
#include <string.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    run_pcap = 0;
    run_live = 0;
    selected = -1;
    ui->tableWidget->setSortingEnabled(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setModel(&model);

    filter.protocol = "";
    filter.sourceIp = "";
    filter.sourcePort = "";
    filter.destinationIp = "";
    filter.destinationPort = "";
}

MainWindow::~MainWindow()
{
    delete ui;
}

QSortFilterProxyModel proxyModel;
Q_DECLARE_METATYPE(pcap_pkthdr);

void MainWindow::on_actionSend_a_crafted_packet_triggered()
{
    sendwindow = new SendPacketWindow(); // Be sure to destroy you window somewhere
    sendwindow->show();
}

void MainWindow::on_actionFilter_Capture_triggered()
{
    qRegisterMetaType<struct s_filter>("filter");
    filterwindow = new FilterWindow();
    connect(filterwindow, SIGNAL(filterValueChanged(struct s_filter)), this, SLOT(filterChanged(struct s_filter)));

    filterwindow->show();
    filterwindow->setFilter(filter);
}

void MainWindow::on_actionClear_Capture_triggered()
{
  this->clear();
}

void MainWindow::on_actionClear_Filter_triggered()
{
    filter.protocol = "";
    filter.sourceIp = "";
    filter.sourcePort = "";
    filter.destinationIp = "";
    filter.destinationPort = "";
    model.packets.clear();
    for (std::vector<paquet>::iterator it = model.allPackets.begin(); it != model.allPackets.end(); ++it) {
        model.addPaquet(*it);
    }
    this->refreshtableWidget();
}

void MainWindow::on_actionOpen_triggered()
{
    qRegisterMetaType<pcap_pkthdr>("pcap_pkthdr");
    this->threadFinished();
    this->clear();
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "",tr("Files(*.pcap)"));
    if (fileName == "")
        return;

    parse = new pcap_analyse();
    parse->window = this;
    thread = new QThread();
   // parse->moveToThread(thread);
    connect(parse, SIGNAL(finished()), thread, SLOT(quit()), Qt::DirectConnection);
    connect(parse, SIGNAL(tvalueChanged(unsigned char *, pcap_pkthdr)), this, SLOT(pcapChanged(unsigned char *, pcap_pkthdr)));
    connect(thread, SIGNAL(started()), parse, SLOT(run()));
    // connect(live, SIGNAL(finished()), thread, SLOT(quit()), Qt::DirectConnection);
    // connect(live, SIGNAL(valueChanged(paquet&)), this, SLOT(on_pcap_analyse_valueChanged(Paquet&)));
    qDebug()<<"Starting thread in Thread "<<this->QObject::thread()->currentThreadId();
    run_pcap = 1;
    // emit(live->run());
        parse->requestPaquet(fileName);
        parse->run();
  //  thread->start();
}

void MainWindow::on_actionStart_Capture_triggered()
{
    if (run_live)
    {
        this->threadFinished();
        ui->menuBar->actions().at(1)->menu()->actions().at(0)->setText("Start Capture"); //actions.at(1)->setText("lol");
               // ui->menuBar-
        return;
    }
    else
        this->threadFinished();
    proxyModel.clear();


    //live_analyse *tmp = new live_analyse();

    live = new live_analyse();
    live->window = this;
    thread = new QThread();
//    qRegisterMetaType("paquet");
    connect(live, SIGNAL(finished()), thread, SLOT(quit()) ,Qt::DirectConnection);
//    connect(live, SIGNAL(finished()), this, SLOT(threadFinished()) ,Qt::DirectConnection);
    connect(live, SIGNAL(tvalueChanged(unsigned char *, int)), this, SLOT(testChanged(unsigned char *, int)));

       live->moveToThread(thread);
       connect(thread, SIGNAL(started()), live, SLOT(run()));
      // connect(live, SIGNAL(finished()), thread, SLOT(quit()), Qt::DirectConnection);
      // connect(live, SIGNAL(valueChanged(paquet&)), this, SLOT(on_pcap_analyse_valueChanged(Paquet&)));
       qDebug()<<"Starting thread in Thread "<<this->QObject::thread()->currentThreadId();
       run_live = 1;
        ui->menuBar->actions().at(1)->menu()->actions().at(0)->setText("Stop Capture");
      // emit(live->run());
       thread->start();
       live->requestPaquet();
   //live->moveToThread(thread)

   //live->run();
}

void MainWindow::refreshtableWidget()
{
    static char init = 0;

//    model.submit();

        // ui->tableWidget->update();
    if (!init){
        init = 1;
            proxyModel.setSourceModel( &model );
      // proxyModel.setSourceModel( &model );
        ui->tableWidget->setModel( &proxyModel );
        QItemSelectionModel *sm = ui->tableWidget->selectionModel();
        connect(sm, SIGNAL(currentRowChanged(QModelIndex,QModelIndex)),
                    this, SLOT(tableWidgetSelectionModel_currentRowChanged(QModelIndex ,QModelIndex)));
        //connect(model,
        //SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
       // model,
       // SLOT(selectionChangedSlot(const QItemSelection &, const QItemSelection &)));
    }

    //ui->tableWidget->setModel(&model);
//    qDebug("%d\n", model.packets.size());
//    ui->tableWidget->setVisible(false);
//    ui->tableWidget->resizeColumnsToContents();
//    ui->tableWidget->setVisible(true);
}

void MainWindow::tableWidgetSelectionModel_currentRowChanged(QModelIndex newSelection,QModelIndex oldSelection)
{
      //QString data = QString::fromUtf8((char*);
    QString data;
    selected = newSelection.row();
    paquet tmp = model.packets.at(newSelection.row());

    data += "source:" + QString::fromStdString(tmp.source) + "\n";
    data += "destination:" + QString::fromStdString(tmp.destination) + "\n";

    ui->textBrowser->setText(data + FormatHexData(tmp.pkt_ptr, tmp.size));
    ui->textBrowser_2->setText(data + FormatData(tmp.pkt_ptr, tmp.size));
    ui->textBrowser_3->setText(FormatHeaderData(&tmp));
}

void MainWindow::on_tableWidget_activated(const QModelIndex &index)
{
 //   qDebug("ok");
}

 void MainWindow::testChanged(unsigned char *buffer, int data_size)
 {
     paquet tmp = paquet(buffer, data_size);
     this->addPaquet(tmp);
 }

 void MainWindow::pcapChanged(unsigned char *buffer,  pcap_pkthdr header)
 {
     unsigned char *copy = (unsigned char*) malloc (sizeof(unsigned char) * header.len);
     void *ptr1 = (char*)copy;
     void *ptr2 = (char*)buffer;
     copy = (unsigned char*)memcpy(ptr1, ptr2 , header.len);
     paquet tmp = paquet(copy, header);
     this->addPaquet(tmp);
 }

 void MainWindow::filterChanged(struct s_filter fil)
 {
     puts("LOL");
     filter = fil;

     model.packets.clear();
     for (std::vector<paquet>::iterator it = model.allPackets.begin(); it != model.allPackets.end(); ++it) {
         if (showPacket(*it)) {
            model.addPaquet(*it);
            this->refreshtableWidget();
         }
     }
 }

 bool MainWindow::showPacket(paquet &p) {
     if (filter.protocol && strlen(filter.protocol)) {
         if (strcmp(p.type.c_str(), filter.protocol)) {
             qDebug("diff protocol");
             qDebug(p.type.c_str());
             qDebug(filter.protocol);
             return false;
         }
     }
     if (filter.sourceIp && strlen(filter.sourceIp)) {
         if (strcmp(p.source.c_str(), filter.sourceIp)) {
             qDebug("diff source ip");
             qDebug(p.source.c_str());
             qDebug(filter.sourceIp);
             return false;
         }
     }
     if (filter.sourcePort && strlen(filter.sourcePort)) {
<<<<<<< HEAD
         if (strcmp(p.sourcePort.c_str(), filter.sourcePort)) {
             qDebug("diff source port");
             qDebug(p.sourcePort.c_str());
             qDebug(filter.sourcePort);
             return false;
=======
         if (!checkFilterToken((char*)p.sourcePort.c_str(), strdup(filter.sourcePort), true)) {
             qDebug("exit sourcePort");
            return false;
>>>>>>> 48d66e78674eb9bc288f50731641ccab8606c67d
         }
     }
     if (filter.destinationIp && strlen(filter.destinationIp)) {
         if (strcmp(p.destination.c_str(), filter.destinationIp)) {
             qDebug("diff dest ip");
             qDebug(p.destination.c_str());
             qDebug(filter.destinationIp);
             return false;
         }
     }
     if (filter.destinationPort && strlen(filter.destinationPort)) {
         if (strcmp(p.destinationPort.c_str(), filter.destinationPort)) {
             qDebug("diff dest port");
             qDebug(p.destinationPort.c_str());
             qDebug(filter.destinationPort);
             return false;
         }
     }
     qDebug("add packet");
     return true;
 }

 void MainWindow::threadFinished()
 {
     if (run_pcap == 1 || run_live == 1 )
     {
         if (run_pcap == 1)
             parse->abort();
         if (run_live == 1)
             live->abort();
         thread->wait();
         delete thread;
         if (run_live == 1 && live)
             delete live;
         if (run_pcap == 1 && parse)
             delete parse;
         run_pcap = 0;
         run_live = 0;
         return;
     }
 }

void MainWindow::addPaquet(paquet &tmp)
{
    if (showPacket(tmp)) {
        this->model.addPaquet(tmp);
        this->refreshtableWidget();
    }
    this->model.allPackets.push_back(tmp);
}

void MainWindow::clear()
{
     model.clear();
     ui->textBrowser->clear();
     ui->textBrowser_2->clear();
     ui->textBrowser_3->clear();
     proxyModel.clear();
     selected = -1;
}

#include <stdio.h>
#include <time.h>
#include <unistd.h>

void MainWindow::on_actionSave_triggered()
{
  pcap_t *handle = pcap_open_dead(DLT_EN10MB, 1 << 16);

  char CurrentPath[FILENAME_MAX];
  getcwd(CurrentPath, sizeof(CurrentPath));
  CurrentPath[sizeof(CurrentPath) - 1] = '\0';

  time_t rawtime;
  struct tm * timeinfo;
  char buffer[80];
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  strftime(buffer, 80, "%d%m%y_%H%M%S.pcap", timeinfo);
  QString filename = QFileDialog::getSaveFileName(this, tr("Save file"), buffer,tr("Files(*.pcap)"));

 // strcat(CurrentPath, buffer);

  pcap_dumper_t *dumper = pcap_dump_open(handle, filename.toStdString().c_str());
  if (dumper == NULL)
      return;
  pcap_pkthdr	pcap_hdr;
  pcap_hdr.caplen = sizeof(uchar *);
  pcap_hdr.len = pcap_hdr.caplen;

  //  std::string pkt_data = "";

  for (std::vector<paquet>::iterator it = model.packets.begin();
       it != model.packets.end(); ++it) {
    pcap_hdr.caplen = it->size; //+ it->ether_offset;
    pcap_hdr.len = it->size; //+ it->ether_offset;
    pcap_hdr.ts.tv_sec = it->date.toTime_t();
    pcap_hdr.ts.tv_usec = it->date.time().msec() * 1000;//(it->date.toMSecsSinceEpoch() - QDateTime::currentMSecsSinceEpoch()) * 1000;
    pcap_dump((uchar *)dumper, &pcap_hdr, it->pkt_ptr);
    //    pkt_data << it->pkt_ptr;
  }
  //  pcap_dump((uchar *)dumper, &pcap_hdr, (const uchar*)pkt_data.c_str());
  pcap_dump_close(dumper);
  std::cout << "Save done. At " << CurrentPath << std::endl;
}

void MainWindow::on_actionModify_and_Send_Selected_Packet_triggered()
{
    if (selected == -1)
        return;
    paquet tmp = model.packets.at(selected);
    sendwindow = new SendPacketWindow(); // Be sure to destroy you window somewhere
    sendwindow->fromPaquet(&tmp);
    sendwindow->show();
}
