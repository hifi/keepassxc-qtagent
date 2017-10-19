#include <QCoreApplication>
#include <QtCore>

#include "SSHAgent/Client.h"
#include "SSHAgent/Identity.h"

#include <iostream>

void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    switch (type) {
        case QtDebugMsg: std::cout << "qDebug: "; break;
        case QtWarningMsg: std::cout << "qWarning: "; break;
        case QtInfoMsg: std::cout << "qInfo: "; break;
        default: break;
    }

    std::cout << msg.toStdString() << std::endl;
}

int main(int argc, char *argv[])
{
    qInstallMessageHandler(messageHandler);

    QFile file("id_rsa");
    file.open(QIODevice::ReadOnly);

    Identity id(file);
    id.parse();

    Client client;
    client.addIdentity(id, "id_rsa");

    /*
    auto identities = client.getIdentities();

    foreach (QSharedPointer<Identity> id, identities) {
        //qInfo() << id;
    }
    */

    return 0;
}
