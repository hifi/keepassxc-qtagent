#include "Client.h"
#include "AgentStream.h"

Client::Client() : m_socketPath(getEnvironmentSocketPath()) { }
Client::Client(QString socketPath) : m_socketPath(socketPath) { }

QString Client::getEnvironmentSocketPath()
{
    auto env = QProcessEnvironment::systemEnvironment();

    if (env.contains("SSH_AUTH_SOCK")) {
        return env.value("SSH_AUTH_SOCK");
    }

    return ""; // should return null or not?
}

QList<Identity>* Client::getIdentities()
{
    AgentStream stream(m_socketPath);
    auto list = new QList<Identity>();

    if (!stream.connect()) {
        return list;
    }

    stream << (quint32) 1; // request size in bytes
    stream << SSH_AGENTC_REQUEST_IDENTITIES;

    quint32 responseLength;
    quint8 responseType;
    quint32 numIdentities;

    stream >> responseLength;
    stream >> responseType;
    stream >> numIdentities;

    if (responseType != SSH_AGENT_IDENTITIES_ANSWER) {
        return list;
    }

    for (quint32 i = 0; i < numIdentities; i++) {
        quint32 keyLength;
        stream >> keyLength;

        // FIXME: hardcoded for RSA keys
        QString keyType;
        QByteArray keyE, keyN;

        stream >> keyType;
        stream >> keyE;
        stream >> keyN;

        QString keyComment;
        stream >> keyComment;

        qInfo() << "keyLength:" << keyLength;
        qInfo() << "keyType:" << keyType;
        qInfo() << "keyE:" << keyE.length() << "bytes";
        qInfo() << "keyN:" << keyN.length() << "bytes";
        qInfo() << "keyComment:" << keyComment;
    }

    return list;
}
