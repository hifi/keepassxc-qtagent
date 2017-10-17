#ifndef CLIENT_H
#define CLIENT_H

#include <QtCore>
#include <QList>
#include "Identity.h"

namespace SSHAgent {
    class Client;
}

class Client
{
public:
    const quint8 SSH_AGENT_FAILURE              = 5;
    const quint8 SSH_AGENT_SUCCESS              = 6;
    const quint8 SSH_AGENTC_REQUEST_IDENTITIES  = 11;
    const quint8 SSH_AGENT_IDENTITIES_ANSWER    = 12;
    const quint8 SSH_AGENTC_ADD_IDENTITY        = 17;

    Client() : m_socketPath(getEnvironmentSocketPath()) { }
    Client(QString socketPath) : m_socketPath(socketPath) { }

    static QString getEnvironmentSocketPath();

    bool addIdentity(Identity&, QString);
    QList<QSharedPointer<Identity>> getIdentities();
    bool removeIdentity(Identity&);

private:
    QString m_socketPath;
};

#endif // CLIENT_H
