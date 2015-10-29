#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QAbstractTableModel>
#include "paquet.h"

class TestModel : public QAbstractTableModel
{
public:
    std::vector<paquet> packets;

    int rowCount(const QModelIndex &parent = QModelIndex()) const
    {
        qDebug("%d",packets.size());
        if (packets.size() == 0)
        return 1;
        return packets.size();
    }
    int columnCount(const QModelIndex &parent = QModelIndex()) const
    {
        return 6;
    }
    QVariant data(const QModelIndex &index, int role) const
    {
        switch (role)
        {
        case Qt::DisplayRole:
        {
            switch (index.column())
            {
            case 0:
                return index.row();
            case 1:
                return packets.at(index.row()).date.toString("dd/MM/yyyy hh:mm:ss:zzz ");
            case 2:
                return packets.at(index.row()).type.c_str();
            case 3:
                return packets.at(index.row()).source.c_str();
            case 4:
                return packets.at(index.row()).destination.c_str();
            case 5:
                return (int)(packets.at(index.row()).size);
            default:
                break;
            }
        }
        }
        return QVariant();
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const
    {
        if (role == Qt::DisplayRole)
        {
            if (orientation == Qt::Horizontal) {
                switch (section)
                {
                case 0:
                    return QString("Numbers");
                case 1:
                    return QString("Date");
                case 2:
                    return QString("Type");
                case 3:
                    return QString("Source");
                case 4:
                    return QString("Destination");
                case 5:
                    return QString("Length");
                }
              if (orientation == Qt::Vertical)
                  return section;
            }
        }
        return QVariant();
    }
};

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    TestModel model;
private slots:
    void on_actionOpen_triggered();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
