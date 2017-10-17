#include "Client.h"
#include "AgentStream.h"

QString Client::getEnvironmentSocketPath()
{
    auto env = QProcessEnvironment::systemEnvironment();

    if (env.contains("SSH_AUTH_SOCK")) {
        return env.value("SSH_AUTH_SOCK");
    }

    return ""; // should return null or not?
}

QList<QSharedPointer<Identity>> Client::getIdentities()
{
    AgentStream stream(m_socketPath);
    QList<QSharedPointer<Identity>> list;

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

    if (responseType == SSH_AGENT_IDENTITIES_ANSWER) {
        stream >> numIdentities;

        for (quint32 i = 0; i < numIdentities; i++) {
            quint32 keyLength;
            stream >> keyLength;

            // FIXME: hardcoded for RSA keys
            QString keyType;
            QByteArray keyE, keyN;
            QString keyComment;

            stream >> keyType;
            stream >> keyE;
            stream >> keyN;
            stream >> keyComment;

            qInfo() << "keyLength:" << keyLength;
            qInfo() << "keyType:" << keyType;
            qInfo() << "keyE:" << keyE.length() << "bytes";
            qInfo() << "keyN:" << keyN.length() << "bytes";
            qInfo() << "keyComment:" << keyComment;

            list.push_back(QSharedPointer<Identity>(new Identity()));
        }
    }

    return list;
}
