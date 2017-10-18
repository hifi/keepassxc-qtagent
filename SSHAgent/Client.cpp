#include "Client.h"
#include "PackStream.h"
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
    PackStream stream(&socket);

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return false;
    }

    QByteArray requestData;
    BinaryStream requestStream(&requestData);

    requestStream.write(SSH_AGENTC_ADD_IDENTITY);
    requestStream.write(identity.toWireFormat());

    // comment needs to be packed
    PackStream requestPackStream(requestStream.getDevice());
    requestPackStream.write(comment);

    stream.write(requestData);
    stream.flush();

    QByteArray responseData;
    stream.read(responseData);

    if (responseData.length() < 0 || (quint8) responseData[0] != SSH_AGENT_SUCCESS)
        return false;

    return true;
}

QList<QSharedPointer<Identity>> Client::getIdentities()
{
    QLocalSocket socket;
    PackStream stream(&socket);
    QList<QSharedPointer<Identity>> list;

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return list;
    }

    // write identities request
    stream.write(SSH_AGENTC_REQUEST_IDENTITIES);

    // read complete response packet
    QByteArray responseData;
    stream.read(responseData);

    BinaryStream responseStream(&responseData);

    quint8 responseType;
    responseStream.read(responseType);

    if (responseType == SSH_AGENT_IDENTITIES_ANSWER) {
        quint32 numIdentities;
        responseStream.read(numIdentities);

        PackStream identityStream(responseStream.getDevice());

        for (quint32 i = 0; i < numIdentities; i++) {
            QByteArray keyData;
            QString keyComment;

            identityStream.read(keyData);
            identityStream.read(keyComment);

            PackStream keyStream(&keyData);

            // FIXME: hardcoded for RSA keys
            QString keyType;
            QByteArray keyE, keyN;

            keyStream.read(keyType);
            keyStream.read(keyE);
            keyStream.read(keyN);

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
