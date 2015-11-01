#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <stdio.h>
#include <QFileDialog>
#include <iostream>
#include <QDebug>
#include <QDateTime>
#include <paquet.h>
#include <pcap_analyse.h>
#include <QSortFilterProxyModel>
#include <QItemSelection>
#include <QString>
#include <sstream>
#include <iomanip>
#include <tools.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
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
   static char init = 0;
   QString fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "",tr("Files(*.pcap)"));
   if (fileName == "")
       return;
   pcap_analyse *parse = new pcap_analyse(fileName);
 //  pcap_analyse *parse = new pcap_analyse("/Users/inso/Study/Secu/network/mypcap.pcap");
   if (init)
        proxyModel.clear();

   model.packets = parse->getPaquets();
   proxyModel.setSourceModel( &model );

   if (!init){
       init = 1;
       ui->tableWidget->setModel( &proxyModel );
       QItemSelectionModel *sm = ui->tableWidget->selectionModel();
       connect(sm, SIGNAL(currentRowChanged(QModelIndex,QModelIndex)),
                   this, SLOT(on_tableWidgetSelectionModel_currentRowChanged(QModelIndex ,QModelIndex)));
       //connect(model,
       //SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
      // model,
      // SLOT(selectionChangedSlot(const QItemSelection &, const QItemSelection &)));
   }

   //ui->tableWidget->setModel(&model);
   qDebug("%d\n", model.packets.size());
   ui->tableWidget->setVisible(false);
   ui->tableWidget->resizeColumnsToContents();
   ui->tableWidget->setVisible(true);
}

void MainWindow::on_tableWidgetSelectionModel_currentRowChanged(QModelIndex newSelection,QModelIndex oldSelection)
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
