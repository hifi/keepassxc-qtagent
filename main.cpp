#include <QCoreApplication>
#include <QtCore>

#include "SSHAgent/Client.h"
#include "SSHAgent/Identity.h"
#include "SSHAgent/PEM.h"

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
    Client client;

    QList<QString> keyNames;
    keyNames.append("id_rsa");
    keyNames.append("id_ed25519");

    foreach (QString keyName, keyNames) {
        QFile file(keyName);
        file.open(QIODevice::ReadOnly);

        PEM pem(file);
        pem.parse();

        Identity* id = pem.getIdentity();
        if (id) {
            qInfo() << "Adding identity to agent";
            client.addIdentity(*id, "id_rsa");
            delete id;
        }
    }

    /*
    auto identities = client.getIdentities();

    foreach (QSharedPointer<Identity> id, identities) {
        //qInfo() << id;
    }
    */

    return 0;
}
