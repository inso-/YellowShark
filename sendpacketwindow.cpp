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
    newPaquet = 1;
}

SendPacketWindow::~SendPacketWindow()
{
    delete ui;
}

void SendPacketWindow::fromPaquet(paquet* model)
{
    _model = model;
  newPaquet = 0;
  ui->packetSourceIp->setText(QString::fromStdString(model->source));
  ui->packetSourcePort->setText(QString::fromStdString(model->sourcePort));
  ui->packetDestinationIp->setText(QString::fromStdString(model->destination));
  ui->packetDestinationPort->setText(QString::fromStdString(model->destinationPort));
  if (model->type == "tcp")
    ui->packetType->setCurrentIndex(0);
  else if (model->type == "udp")
    ui->packetType->setCurrentIndex(1);
  else if (model->type == "icmp")
    ui->packetType->setCurrentIndex(2);

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
    paquet *crafted;
    if (newPaquet == 0 )
    crafted = new paquet(type.toStdString(),
                                 sourceIp.toStdString(),
                                 sourcePort.toStdString(),
                                 destinationIp.toStdString(),
                                 destinationPort.toStdString(),
                                 data.toStdString());
    else if (type.toStdString() != _model->type)
        crafted = new paquet(type.toStdString(),
                                     sourceIp.toStdString(),
                                     sourcePort.toStdString(),
                                     destinationIp.toStdString(),
                                     destinationPort.toStdString(),
                                     data.toStdString());
    else
    {
      crafted = _model;
    }
    crafted->send(atoi(number.toStdString().c_str()));
    qDebug() << "Packet send to " << destinationIp << ":" << destinationPort;
}

void SendPacketWindow::on_buttonBox_rejected()
{
}
