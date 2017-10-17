#include <QCoreApplication>
#include <QtCore>

#include "SSHAgent/Client.h"

int main(int argc, char *argv[])
{
    Client client;
    auto identities = client.getIdentities();

    foreach (QSharedPointer<Identity> id, identities) {
        //qInfo() << id;
    }

    return 0;
}
