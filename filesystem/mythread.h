#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QObject>
#include <QString>
#include "header.h"
class MyThread:public QObject
{
Q_OBJECT
public:
    MyThread(antivirus_scaner name);
public slots:
void doWork();
signals:
void send(int);
private:
QString name;
};

#endif // MYTHREAD_H
