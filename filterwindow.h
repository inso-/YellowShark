#ifndef FILTERWINDOW_H
#define FILTERWINDOW_H

#include <QDialog>

typedef struct s_filter{
}filter;

namespace Ui {
class FilterWindow;
}

class FilterWindow : public QDialog
{
    Q_OBJECT

public:
    explicit FilterWindow(QWidget *parent = 0);
    ~FilterWindow();

private:
    Ui::FilterWindow *ui;
    struct s_filter filter;
signals:
    void filterValueChanged(struct s_filter);
private slots:
    void on_buttonBox_accepted();
};

#endif // FILTERWINDOW_H
