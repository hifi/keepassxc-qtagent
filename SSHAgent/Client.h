#ifndef CLIENT_H
#define CLIENT_H

#include <QList>
#include "Identity.h"

namespace SSHAgent {
    class Client;
}

class Client
{
public:
    const quint8 SSH_AGENTC_REQUEST_IDENTITIES  = 11;
    const quint8 SSH_AGENT_IDENTITIES_ANSWER    = 12;

    Client();
    Client(QString);

    static QString getEnvironmentSocketPath();

    QList<Identity>* getIdentities();
    bool removeIdentity(Identity);

private:
    QString m_socketPath;
};

#endif // CLIENT_H
