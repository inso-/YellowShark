#ifndef SENDPACKETWINDOW_H
#define SENDPACKETWINDOW_H

#include <QDialog>
#include "paquet.h"

namespace Ui {
class SendPacketWindow;
}

class SendPacketWindow : public QDialog
{
    Q_OBJECT

public:
    explicit SendPacketWindow(QWidget *parent = 0);
    ~SendPacketWindow();
    void fromPaquet(paquet* model);
    int newPaquet;

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    paquet *_model;
    Ui::SendPacketWindow *ui;
};

#endif // SENDPACKETWINDOW_H
