#include "filterwindow.h"
#include "ui_filterwindow.h"
#include <QDebug>

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

    filter.protocol = strdup(type.toStdString().c_str());
    filter.sourceIp = strdup(sourceIp.toStdString().c_str());
    filter.sourcePort = strdup(sourcePort.toStdString().c_str());
    filter.destinationIp = strdup(destinationIp.toStdString().c_str());
    filter.destinationPort = strdup(destinationPort.toStdString().c_str());

    emit filterValueChanged(filter);
}
