#include "AgentStream.h"
#include <QtEndian>

AgentStream::AgentStream(QString socketPath)
{
    m_socket.setServerName(socketPath);
}

bool AgentStream::connect()
{
    m_socket.connectToServer();

    if (!m_socket.waitForConnected(500)) {
        return false;
    }

    return true;
}

bool AgentStream::read(uchar *ptr, qint64 size)
{
    qint64 pos = 0;

    while (pos < size) {
        if (m_socket.bytesAvailable() == 0) {
            m_socket.waitForReadyRead(-1);
        }

        qint64 nread = m_socket.read((char *)(ptr + pos), size - pos);

        if (nread == -1) {
            qInfo() << "read error:" << m_socket.errorString();
            return false;
        }

        pos += nread;
    }

    return true;
}

bool AgentStream::write(uchar *ptr, qint64 size)
{
    m_socket.write((char *)ptr, size);
    m_socket.waitForBytesWritten(-1);
    return true;
}

AgentStream& AgentStream::operator<<(quint8 i)
{
    // this conversion is a no-op but for completeness leaving it like this for now
    uchar data[1];
    qToBigEndian(i, data);
    write(data, 1);
    return *this;
}

AgentStream& AgentStream::operator<<(quint32 i)
{
    uchar data[4];
    qToBigEndian(i, data);
    write(data, sizeof data);
    return *this;
}

AgentStream& AgentStream::operator>>(quint8 &i)
{
    // this conversion is a no-op but for completeness leaving it like this for now
    uchar data[1];
    read(data, sizeof data);
    i = qFromBigEndian<quint8>(data);
    return *this;
}

AgentStream& AgentStream::operator>>(quint32 &i)
{
    uchar data[4];
    read(data, sizeof data);
    i = qFromBigEndian<quint32>(data);
    return *this;
}

AgentStream& AgentStream::operator>>(QByteArray &ba)
{
    quint32 len;
    *this >> len;
    ba.resize(len);

    read((uchar *)ba.data(), ba.length());

    return *this;
}

AgentStream& AgentStream::operator>>(QString &s)
{
    QByteArray data;
    *this >> data;

    s = QString::fromUtf8(data);

    return *this;
}
