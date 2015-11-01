#include "sendpacketwindow.h"
#include "ui_sendpacketwindow.h"

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
