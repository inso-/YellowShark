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

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    run_pcap = 0;
    run_live = 0;
    ui->tableWidget->setSortingEnabled(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setModel(&model);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QSortFilterProxyModel proxyModel;

void MainWindow::on_actionOpen_triggered()
{


 //  pcap_analyse *parse = new pcap_analyse("/Users/inso/Study/Secu/network/mypcap.pcap");

    this->getDataFromFile();
   //auto func = std::bind(&MainWindow::getDataFromFile, this, std::placeholders::_1);

   //auto f = std::async(std::launch::async, func, 0);

  // QFuture<void> future = QtConcurrent::run(func);
//   auto f = async(std::launch::async, func, 0);
  // model.packets = f.get();

}

    Q_DECLARE_METATYPE(pcap_pkthdr);

void MainWindow::getDataFromFile()
{
qRegisterMetaType<pcap_pkthdr>("pcap_pkthdr");
  //  proxyModel.clear();
  //  this->refreshtableWidget();
   // parse->getPaquets();

    if (run_pcap == 1 || run_live == 1 )
    {
//        ui->menuBar->
        if (run_pcap == 1)
            parse->abort();
        if (run_live == 1)
            live->abort();
        thread->wait();
        run_pcap = 0;
        run_live = 0;
        delete thread;
        delete live;
        delete parse;
        return;
    }
      proxyModel.clear();
      QString fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "",tr("Files(*.pcap)"));
      if (fileName == "")
          return;
      parse = new pcap_analyse();

    //live_analyse *tmp = new live_analyse();
    parse->window = this;
    thread = new QThread();
//    qRegisterMetaType("paquet");

       parse->moveToThread(thread);
       connect(parse, SIGNAL(finished()), thread, SLOT(quit()), Qt::DirectConnection);
       connect(parse, SIGNAL(tvalueChanged(unsigned char *, pcap_pkthdr)), this, SLOT(pcapChanged(unsigned char *, pcap_pkthdr)));
       connect(thread, SIGNAL(started()), parse, SLOT(run()));
      // connect(live, SIGNAL(finished()), thread, SLOT(quit()), Qt::DirectConnection);
      // connect(live, SIGNAL(valueChanged(paquet&)), this, SLOT(on_pcap_analyse_valueChanged(Paquet&)));
       qDebug()<<"Starting thread in Thread "<<this->QObject::thread()->currentThreadId();
       run_pcap = 1;
      // emit(live->run());
       thread->start();
       parse->requestPaquet(fileName);



//    this->refreshtableWidget();
//    proxyModel.setSourceModel( &model );

//    if (!init){
//        init = 1;
//        ui->tableWidget->setModel( &proxyModel );
//        QItemSelectionModel *sm = ui->tableWidget->selectionModel();
//        connect(sm, SIGNAL(currentRowChanged(QModelIndex,QModelIndex)),
//                    this, SLOT(on_tableWidgetSelectionModel_currentRowChanged(QModelIndex ,QModelIndex)));
//        //connect(model,
//        //SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
//       // model,
//       // SLOT(selectionChangedSlot(const QItemSelection &, const QItemSelection &)));
//    }

//    //ui->tableWidget->setModel(&model);
//    qDebug("%d\n", model.packets.size());
//    ui->tableWidget->setVisible(false);
//    ui->tableWidget->resizeColumnsToContents();
//    ui->tableWidget->setVisible(true);
//}
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
    paquet tmp = model.packets.at(newSelection.row());

    data += "source:" + QString::fromStdString(tmp.source) + "\n";
    data += "destination:" + QString::fromStdString(tmp.destination) + "\n";

    ui->textBrowser->setText(data + FormatHexData(tmp.pkt_ptr, tmp.size));
    ui->textBrowser_2->setText(data + FormatData(tmp.pkt_ptr, tmp.size));
}

void MainWindow::on_tableWidget_activated(const QModelIndex &index)
{
    qDebug("ok");
}

void MainWindow::on_actionSend_a_crafted_packet_triggered()
{
    sendwindow = new SendPacketWindow(); // Be sure to destroy you window somewhere
    sendwindow->show();
}

void MainWindow::on_actionFilter_Capture_triggered()
{
    filterwindow = new FilterWindow();
    filterwindow->show();
}

void MainWindow::on_actionStart_Capture_triggered()
{

    if (run_pcap == 1 || run_live == 1 )
    {
//        ui->menuBar->
        if (run_pcap == 1)
            parse->abort();
        if (run_live == 1)
            live->abort();
        thread->wait();
        run_pcap = 0;
        run_live = 0;
        delete thread;
        delete live;
        delete parse;
        return;
    }
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
      // emit(live->run());
       thread->start();
       live->requestPaquet();
   //live->moveToThread(thread)

   //live->run();
}

 void MainWindow::testChanged(unsigned char *buffer, int data_size)
 {
     printf("paquet to add ___ here __:\n");
     paquet tmp = paquet(buffer, data_size);
     this->model.addPaquet(tmp); // .packets.push_back(tmp);
     this->refreshtableWidget();
 }

 void MainWindow::pcapChanged(unsigned char *buffer,  pcap_pkthdr header)
 {
     printf("paquet to add ___ here __:\n");
     paquet tmp = paquet(buffer, header);
     this->model.addPaquet(tmp); // .packets.push_back(tmp);
     this->refreshtableWidget();
 }
 void MainWindow::threadFinished()
 {

    if (run_pcap == 1)
        parse->abort();
    if (run_live == 1)
        live->abort();
    run_live = 0;
    run_pcap = 0;
  //  thread->wait();
    // thread->quit();
    // delete thread;
     delete parse;
     delete live;

 }

// void MainWindow::packetsChanged(unsigned char *buffer, int data_size)
// {

// }
