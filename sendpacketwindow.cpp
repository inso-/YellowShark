#include "sendpacketwindow.h"
#include "ui_sendpacketwindow.h"
#include "paquet.h"
#include <stdio.h>
#include <string.h>
#include <QtDebug>

SendPacketWindow::SendPacketWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendPacketWindow)
{
    ui->setupUi(this);
}

SendPacketWindow::~SendPacketWindow()
{
    delete ui;
}

void SendPacketWindow::on_buttonBox_accepted()
{
//    QString type = ui->packetType->itemData(ui->packetType->currentIndex());
    QString type = ui->packetType->currentText();
    QString sourceIp = ui->packetSourceIp->text();
    QString sourcePort = ui->packetSourcePort->text();
    QString destinationIp = ui->packetDestinationIp->text();
    QString destinationPort = ui->packetDestinationPort->text();
    QString data = ui->packetData->toPlainText();
    QString number = ui->PacketNumber->text();
    qDebug("On button send packet");
    qDebug() << type;
    qDebug() << sourceIp;
    qDebug() << sourcePort;
    qDebug() << destinationIp;
    qDebug() << destinationPort;
    qDebug() << data;

    paquet *crafted = new paquet(type.toStdString(),
                                 sourceIp.toStdString(),
                                 sourcePort.toStdString(),
                                 destinationIp.toStdString(),
                                 destinationPort.toStdString(),
                                 data.toStdString());
    crafted->send(atoi(number.toStdString().c_str()));
    qDebug() << "Packet send to " << destinationIp << ":" << destinationPort;
}

void SendPacketWindow::on_buttonBox_rejected()
{
}
