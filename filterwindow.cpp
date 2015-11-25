#include "filterwindow.h"
#include "ui_filterwindow.h"

FilterWindow::FilterWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterWindow)
{
    ui->setupUi(this);
    }

FilterWindow::~FilterWindow()
{
    delete ui;
}

void FilterWindow::on_buttonBox_accepted()
{
    QString type = ui->packetType->text();
    QString sourceIp = ui->packetSourceIp->text();
    QString sourcePort = ui->packetSourcePort->text();
    QString destinationIp = ui->packetDestinationIp->text();
    QString destinationPort = ui->packetDestinationPort->text();

    filter.protocol = type.toStdString().c_str();
    filter.sourceIp = sourceIp.toStdString().c_str();
    filter.sourcePort = sourcePort.toStdString().c_str();
    filter.destinationIp = destinationIp.toStdString().c_str();
    filter.destinationPort = destinationPort.toStdString().c_str();

    emit filterValueChanged(filter);
}
