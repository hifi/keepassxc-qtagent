#include <QCoreApplication>
#include <QtCore>

#include "SSHAgent/Client.h"
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

    keyNames.append("id_dsa");
    keyNames.append("id_rsa");
    keyNames.append("id_ed25519");
    keyNames.append("id_rsa_new");
    keyNames.append("id_dsa_new");
    keyNames.append("id_ecdsa_new");

    qInfo() << "Adding identities";

    foreach (QString keyName, keyNames) {
        QFile file(keyName);
        file.open(QIODevice::ReadOnly);

        PEM pem(file);
        pem.parse();

        QList<QSharedPointer<OpenSSHKey>> keys = pem.getKeys();
        foreach (QSharedPointer<OpenSSHKey> key, keys) {
            OpenSSHKey *k = key.data();

            qInfo() << k->getKeyLength() << k->getFingerprint() << k->getComment() << k->getType();

            client.addIdentity(*key);
        }
    }

    qInfo() << "Reading identities";

    auto identities = client.getIdentities();

    foreach (QSharedPointer<OpenSSHKey> key, identities) {
        OpenSSHKey *k = key.data();
        qInfo() << k->getKeyLength() << k->getFingerprint() << k->getComment() << k->getType();
    }

    return 0;
}
