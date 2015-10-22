#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <stdio.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <QFileDialog>
#include <iostream>
#include <QDebug>
#include <QDateTime>
#include <paquet.h>
#include <pcap_analyse.h>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}



void MainWindow::on_actionOpen_triggered()
{
   QString fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "",tr("Files(*.pcap)"));
   qDebug(fileName.toLatin1());
   pcap_analyse parse = pcap_analyse(fileName);

   parse.getPaquets();
}
