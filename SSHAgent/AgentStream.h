#ifndef AGENTSOCKET_H
#define AGENTSOCKET_H

#include <QtCore>
#include <QtNetwork>

namespace SSHAgent {
    class AgentStream;
}

class AgentStream
{
public:
    AgentStream(QString socketPath);

    bool connect();

    bool read(uchar *ptr, qint64 size);
    bool write(uchar *ptr, qint64 size);

    AgentStream& operator<<(quint8);
    AgentStream& operator<<(quint32);
    AgentStream& operator<<(QByteArray&);
    AgentStream& operator<<(QString&);

    AgentStream& operator>>(QByteArray&);
    AgentStream& operator>>(quint8&);
    AgentStream& operator>>(quint32&);
    AgentStream& operator>>(QString&);

private:
    QLocalSocket m_socket;
};

#endif // AGENTSOCKET_H
