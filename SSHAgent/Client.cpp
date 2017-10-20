#include "Client.h"
#include "BinaryStream.h"
#include <QtNetwork>

QString Client::getEnvironmentSocketPath()
{
    auto env = QProcessEnvironment::systemEnvironment();

    if (env.contains("SSH_AUTH_SOCK")) {
        return env.value("SSH_AUTH_SOCK");
    }

    return ""; // should return null or not?
}

bool Client::addIdentity(OpenSSHKey &key, quint32 lifetime)
{
    QLocalSocket socket;
    BinaryStream stream(&socket);

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return false;
    }

    QByteArray requestData;
    BinaryStream request(&requestData);

    request.write(lifetime > 0 ? SSH_AGENTC_ADD_ID_CONSTRAINED : SSH_AGENTC_ADD_IDENTITY);
    key.writePrivate(request);

    if (lifetime > 0) {
        request.write(SSH_AGENT_CONSTRAIN_LIFETIME);
        request.write(lifetime);
    }

    stream.writePack(requestData);
    stream.flush();

    QByteArray responseData;
    stream.read(responseData);

    if (responseData.length() < 1 || (quint8) responseData[0] != SSH_AGENT_SUCCESS)
        return false;

    return true;
}

QList<QSharedPointer<OpenSSHKey>> Client::getIdentities()
{
    QLocalSocket socket;
    BinaryStream stream(&socket);
    QList<QSharedPointer<OpenSSHKey>> list;

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return list;
    }

    // write identities request
    stream.writePack(SSH_AGENTC_REQUEST_IDENTITIES);

    // read complete response packet
    QByteArray responseData;
    stream.readPack(responseData);

    BinaryStream responseStream(&responseData);

    quint8 responseType;
    responseStream.read(responseType);

    if (responseType == SSH_AGENT_IDENTITIES_ANSWER) {
        quint32 numIdentities;
        responseStream.read(numIdentities);

        for (quint32 i = 0; i < numIdentities; i++) {
            QByteArray keyData;
            QString keyComment;

            responseStream.readPack(keyData);
            responseStream.readPack(keyComment);

            BinaryStream keyStream(&keyData);

            OpenSSHKey *key = new OpenSSHKey();

            if (key->readPublic(keyStream)) {
                key->setComment(keyComment);
                list.append(QSharedPointer<OpenSSHKey>(key));
            } else {
                delete key;
            }
        }
    }

    return list;
}

bool Client::removeIdentity(OpenSSHKey& identity)
{
    return false;
}
