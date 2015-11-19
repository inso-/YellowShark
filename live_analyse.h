 #ifndef LIVE_ANALYSE_H
#define LIVE_ANALYSE_H
#include <vector>
#include <paquet.h>
//#include <mainwindow.h>
#include <QEventLoop>
//#include <QThread>
//#include <QTimer>
#include <QWaitCondition>
#include <QObject>
#include <QMutex>

class MainWindow;

class live_analyse : public QObject
{
        Q_OBJECT
   public:
        explicit live_analyse(QObject *parent = 0); // :
//        QObject(parent)
//    {
//        _abort = false;
//        _interrupt = false;
//        //window = (MainWIndow*)parent;
//    };

    //live_analyse(MainWindow *windows);
    void abort();
    QWaitCondition condition;
    MainWindow* window;
    bool _abort;
    bool _interrupt;
    QMutex mutex;
        void requestPaquet();
signals:
    void tvalueChanged(unsigned char *, int);
    void finished();

public slots:
    void run();

};

#endif // LIVE_ANALYSE_H
