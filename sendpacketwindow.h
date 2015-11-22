#ifndef SENDPACKETWINDOW_H
#define SENDPACKETWINDOW_H

#include <QDialog>


namespace Ui {
class SendPacketWindow;
}

class SendPacketWindow : public QDialog
{
    Q_OBJECT

public:
    explicit SendPacketWindow(QWidget *parent = 0);
    ~SendPacketWindow();

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    Ui::SendPacketWindow *ui;
};

#endif // SENDPACKETWINDOW_H
