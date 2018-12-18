#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include "header.h"
#include <QtCore>
#include <QDir>
#include <QFileSystemModel>
#include <QtGui>
#include <QMainWindow>
#include <QtNetwork/QNetworkReply>


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow, public ilogger
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void test();

private:
    Ui::MainWindow *ui;
    QFileSystemModel * model;
    QNetworkAccessManager manager;
    QNetworkReply *reply;
    QString answer, resource, scan_id;
    QFileInfo path, name;

signals:
    void finish();

public slots:
    void getReplyFinished();
    void readyReadReply();
    void checkReport();
    void write(QString);
    void finish_scanning_directory();
    void finish_scanning_registry();

private slots:
    void on_listView_doubleClicked(const QModelIndex &index);

    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();

    void on_listView_clicked(const QModelIndex &index);

    void on_action_4_triggered();

    virtual void log(const std::string& message);

    void on_pushButton_5_clicked();

    void on_pushButton_6_clicked();

    void on_pushButton_7_clicked();
};

#endif // MAINWINDOW_H
