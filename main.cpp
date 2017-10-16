#include <QCoreApplication>
#include <QtCore>

#include "SSHAgent/Client.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qInfo() << "Creating new client";
    auto client = new Client();

    qInfo() << "Going to fetch identities";
    auto identities = client->getIdentities();
    qInfo() << "Got 'em";

    foreach (Identity id, *identities) {
        //qInfo() << id;
    }

    delete identities;

    return a.exec();
}
