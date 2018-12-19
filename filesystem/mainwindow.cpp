#include "mainwindow.h"
#include <QtCore>
#include <QDebug>
#include <QMessageBox>
#include <QScrollBar>
#include <QString>
#include <qstring.h>
#include "ui_mainwindow.h"

QFileInfo fileinfor;
antivirusScaner scaner;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    model=new QFileSystemModel(this);
    model->setFilter(QDir::QDir::AllEntries);
    model->setRootPath("");
    ui->listView->setModel(model);
    scaner.set_logger(this);
    connect(&scaner, SIGNAL(send_for_writing(QString)), this, SLOT(write(QString)));
    connect(&scaner, SIGNAL(finish_checking_directory()), this, SLOT(finish_scanning_directory()));
    connect(&scaner, SIGNAL(finish_checking_registry()), this, SLOT(finish_scanning_registry()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_listView_doubleClicked(const QModelIndex &index)
{

    QListView * listview = (QListView *) sender();
    QFileInfo fileinfo = model->fileInfo(index);
    if(fileinfo.fileName()=="..")
    {
        QDir dir = fileinfo.dir();
        dir.cdUp();
        listview->setRootIndex(model->index(dir.absolutePath()));
    }
    else if(fileinfo.fileName()==".")
    {
        listview->setRootIndex(model->index(""));
    }
    else if(fileinfo.isDir())
    {
        listview->setRootIndex(index);
    }
}
void MainWindow::on_listView_clicked(const QModelIndex &index)
{
    QModelIndexList lst=ui->listView->selectionModel()->selectedIndexes();
    fileinfor = model->filePath(lst.at(0));
    QString str=fileinfor.dir().absolutePath() + '/' + fileinfor.fileName();
}

void MainWindow::finish_scanning_directory()
{
    if(scaner.counter_()==0)
        QMessageBox::information(this,"Notification","All right in this dir");
    else {
        QMessageBox::information(this,"Notification","Dangerous files were moved to carantin");
        QMessageBox::information(this,"Notification","Moved " + QString::number(scaner.counter_()) + " files");
    }

    scaner.name_of_scan = "";
}

void MainWindow::finish_scanning_registry()
{
    if(scaner.counter_()==0)
        QMessageBox::information(this,"Notification","All right in registr");
    else {
        QString str = "Dangerous files were found\nPlease, delete these values from your registr:\n";

        for (auto & i : scaner.valuesAndKeys) {
            str += i + '\n';
        }

        QMessageBox::information(this,"Notification", str);
        system("regedit");
        //QMessageBox::information(this,"Notification","Moved " + QString::number(scaner.counter_()) + " files");
    }
}

void MainWindow::write(QString string) {
    scaner.logger->log(string.toUtf8().constData());
}

void MainWindow::on_pushButton_2_clicked()
{
    scaner.new_count();
    scaner.name_of_scan = fileinfor.dir().absolutePath() + '/' + fileinfor.fileName();
    scaner.directory = true;
    scaner.start();
}

void MainWindow::on_pushButton_3_clicked()
{
    scaner.new_count();
    scaner.directory = false;
    scaner.start();
}

void MainWindow::checkReport() {
    answer = QString::fromUtf8(reply->readAll());

    for (auto & i : answer) {
        if (i != '<' && i != '>' && i != '"' && i != '{' && i != '}') {
            char p = i.toLatin1();
            QString str(p);
            if (str != ',')
                scaner.logger->log(str.toUtf8().constData());
            else
                scaner.logger->log("\n");
        }
    }
    scaner.logger->log("\n");
    if(answer.contains("Scan finished, information embedded")) {
        QStringList list1 = answer.split("\"positives\": ");
        QStringList list2 = list1[1].split(",");
        QString checking_file = path.dir().absolutePath() + '/' + name.fileName();

        if(list2[0] == '0') {
           QString str = "Don`t worry, " + checking_file + " checked file is not dangerous";
           scaner.logger->log(str.toUtf8().constData());
        }
        else {
           QString str = "File " + checking_file + " is dangerous, so it has been replaced in carantin";
           scaner.move_file(path.dir().absolutePath().toUtf8().constData(), name.fileName().toUtf8().constData());
           scaner.logger->log(str.toUtf8().constData());
        }
    }
    else
        if (answer.contains("Your resource is queued for analysis")) {
            scaner.logger->log("Report isn`t ready. Please, w8 and read some quotes\n");
        }
}

void MainWindow::on_action_4_triggered()
{
    QUrl apiUrl("https://www.virustotal.com/vtapi/v2/file/report");
    QByteArray str = "apikey=79741e0b3add3b7675fd6c8bedef60d85fd51082dbe288d5ba01eeb434b1d56e&resource=";
    str += resource;
    str += "&scan_id=" + scan_id;
    QByteArray requestString(str);
    QNetworkRequest request(apiUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader,"application/x-www-form-urlencoded");
    reply = manager.post(request, requestString);
    connect(reply, SIGNAL(finished()),this, SLOT(getReplyFinished()));
    connect(reply, SIGNAL(readChannelFinished()), this, SLOT(checkReport()));
}


void MainWindow::log(const std::string& message)
{
    QString str = QString::fromStdString(message);
    ui->textEdit->insertPlainText(str);
    QScrollBar* sb = ui->textEdit->verticalScrollBar();
    sb->setValue(sb->maximum());
    repaint();
}

void MainWindow::on_pushButton_5_clicked()
{
    ui->textEdit->clear();
}

void MainWindow::on_pushButton_6_clicked()
{
    scaner.terminate();
    scaner.logger->log("\n\nScanning has been interrupted\n");
}

void MainWindow::getReplyFinished() {
    reply->deleteLater();
}

void MainWindow::readyReadReply() {
    resource = QString::fromUtf8(reply->readAll());
    QStringList list1 = resource.split("\"resource\": \"");
    QStringList list2 = list1[1].split("\"");
    resource = list2[0];
    QStringList list3 = list1[0].split("scan_id\": \"");
    list2 = list3[1].split("\"");
    scan_id = list2[0];
}

void MainWindow::test() {
    QUrl apiUrl("https://www.virustotal.com/vtapi/v2/file/scan");
    QByteArray str = "apikey=79741e0b3add3b7675fd6c8bedef60d85fd51082dbe288d5ba01eeb434b1d56e&file=";
    str += fileinfor.dir().absolutePath() + '/' + fileinfor.fileName();
    path = fileinfor.dir().absolutePath();
    name = fileinfor.fileName();
    QString inf = fileinfor.dir().absolutePath() + '/' + fileinfor.fileName();
    QFileInfo finf=inf;
    if(!(finf.isFile())){
        scaner.logger->log("File isn't chosen \n");
        return;
    }
    else {
        QByteArray requestString(str);
        QNetworkRequest request(apiUrl);
        request.setHeader(QNetworkRequest::ContentTypeHeader,"application/x-www-form-urlencoded");
        reply = manager.post(request, requestString);
        connect(reply, SIGNAL(finished()),this, SLOT(getReplyFinished()));
        connect(reply, SIGNAL(readChannelFinished()), this, SLOT(readyReadReply()));
        scaner.logger->log("File is scanning by VirusTotal...\nIf you want to know result of scanning, push \"Take Report\"\n");
    }
}

void MainWindow::on_pushButton_7_clicked()
{
    test();
}
