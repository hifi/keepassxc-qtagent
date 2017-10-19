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

bool Client::addIdentity(Identity& identity, QString comment)
{
    QLocalSocket socket;
    BinaryStream stream(&socket);

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return false;
    }

    QByteArray requestData;
    BinaryStream request(&requestData);

    request.write(SSH_AGENTC_ADD_IDENTITY);
    request.write(identity.toWireFormat());
    request.writePack(comment);

    stream.writePack(requestData);
    stream.flush();

    QByteArray responseData;
    stream.read(responseData);

    if (responseData.length() < 1 || (quint8) responseData[0] != SSH_AGENT_SUCCESS)
        return false;

    return true;
}

QList<QSharedPointer<Identity>> Client::getIdentities()
{
    QLocalSocket socket;
    BinaryStream stream(&socket);
    QList<QSharedPointer<Identity>> list;

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

            // FIXME: hardcoded for RSA keys
            QString keyType;
            QByteArray keyE, keyN;

            keyStream.readPack(keyType);
            keyStream.readPack(keyE);
            keyStream.readPack(keyN);

            qInfo() << "keyType:" << keyType;
            qInfo() << "keyE:" << keyE.length() << "bytes";
            qInfo() << "keyN:" << keyN.length() << "bytes";
            qInfo() << "keyComment:" << keyComment;

            //list.push_back(QSharedPointer<Identity>(new Identity()));
        }
    }

    return list;
}

bool Client::removeIdentity(Identity& identity)
{
    return false;
}
