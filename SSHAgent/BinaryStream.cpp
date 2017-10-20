#include "BinaryStream.h"
#include <QtEndian>

BinaryStream::BinaryStream(QByteArray *ba, QObject *parent) : QObject(parent)
{
    m_buffer = new QBuffer(ba);
    m_buffer->open(QIODevice::ReadWrite);

    m_dev = m_buffer;
}

BinaryStream::~BinaryStream()
{
    if (m_buffer) {
        delete m_buffer;
    }
}

const QString BinaryStream::errorString()
{
    return m_error;
}

QIODevice* BinaryStream::getDevice()
{
    return m_dev;
}

void BinaryStream::setDevice(QIODevice *dev)
{
    m_dev = dev;
}

void BinaryStream::setTimeout(int timeout)
{
    m_timeout = timeout;
}

bool BinaryStream::read(char *ptr, qint64 size)
{
    qint64 pos = 0;

    while (pos < size) {
        if (m_dev->bytesAvailable() == 0) {
            if (!m_dev->waitForReadyRead(m_timeout)) {
                m_error = m_dev->errorString();
                return false;
            }
        }

        qint64 nread = m_dev->read(ptr + pos, size - pos);

        if (nread == -1) {
            m_error = m_dev->errorString();
            return false;
        }

        pos += nread;
    }

    return true;
}

bool BinaryStream::read(QByteArray &ba)
{
    return read(ba.data(), ba.length());
}

bool BinaryStream::read(quint32 &i)
{
    if (read((char *)&i, sizeof(i))) {
        i = qFromBigEndian<quint32>(i);
        return true;
    }

    return false;
}

bool BinaryStream::read(quint16 &i)
{
    if (read((char *)&i, sizeof(i))) {
        i = qFromBigEndian<quint16>(i);
        return true;
    }

    return false;
}

bool BinaryStream::read(quint8 &i)
{
    return read((char *)&i, sizeof(i));
}

bool BinaryStream::readPack(QByteArray &ba)
{
   quint32 length;

   if (!read(length))
       return false;

   ba.resize(length);

   if (!read(ba.data(), ba.length()))
       return false;

   return true;
}

bool BinaryStream::readPack(QString &str)
{
    QByteArray ba;

    if (!readPack(ba))
        return false;

    str = str.fromLatin1(ba);
    return true;
}


bool BinaryStream::write(const char *ptr, qint64 size)
{
    if (m_dev->write(ptr, size) < 0) {
        m_error = m_dev->errorString();
        return false;
    }

    return true;
}

bool BinaryStream::flush()
{
    if (!m_dev->waitForBytesWritten(m_timeout)) {
        m_error = m_dev->errorString();
        return false;
    }

    return true;
}

bool BinaryStream::write(const QByteArray &ba)
{
    return write(ba.data(), ba.length());
}

bool BinaryStream::write(quint32 i)
{
    i = qToBigEndian<quint32>(i);
    return write((char *)&i, sizeof(i));
}

bool BinaryStream::write(quint8 i)
{
    return write((char *)&i, sizeof(i));
}

bool BinaryStream::writePack(const QByteArray &ba)
{
    if (!write((quint32) ba.length()))
        return false;
    if (!write(ba))
        return false;

    return true;
}

bool BinaryStream::writePack(const QString &s)
{
    return writePack(s.toLatin1());
}

bool BinaryStream::writePack(quint8 i)
{
    if (!write((quint32) sizeof(i)))
        return false;
    if (!write(i))
        return false;

    return true;
}
