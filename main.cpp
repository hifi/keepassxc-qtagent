#include <QCoreApplication>
#include <QtCore>

#include "SSHAgent/Client.h"
#include "SSHAgent/Identity.h"

int main(int argc, char *argv[])
{
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
