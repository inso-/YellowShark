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

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget->setSortingEnabled(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QSortFilterProxyModel proxyModel;

void MainWindow::on_actionOpen_triggered()
{
    model.packets = null;
   QString fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "",tr("Files(*.pcap)"));
   qDebug(fileName.toLatin1());
   pcap_analyse *parse = new pcap_analyse(fileName);
//   pcap_analyse *parse = new pcap_analyse("/Users/inso/Study/Secu/network/mypcap.pcap");

   model.packets = parse->getPaquets();
 //  QSortFilterProxyModel proxyModel;
   proxyModel.setSourceModel( &model );
   ui->tableWidget->setModel( &proxyModel );
   //ui->tableWidget->setModel(&model);
   qDebug("%d\n", model.packets.size());
}
