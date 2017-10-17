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

    AgentStream& operator<<(quint8 i);
    AgentStream& operator<<(quint32 i);

    AgentStream& operator>>(QByteArray &s);
    AgentStream& operator>>(quint8 &i);
    AgentStream& operator>>(quint32 &i);
    AgentStream& operator>>(QString &s);

private:
    QLocalSocket m_socket;
};

#endif // AGENTSOCKET_H
