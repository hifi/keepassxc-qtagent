#ifndef PACKSTREAM_H
#define PACKSTREAM_H

#include "BinaryStream.h"
#include <QBuffer>

class PackStream : public BinaryStream
{
public:
    using BinaryStream::BinaryStream;

    using BinaryStream::read;
    bool read(QByteArray &ba);
    bool read(QString &str);

    using BinaryStream::write;
    bool write(const QByteArray &ba);
    bool write(const QString &str);
    bool write(quint8 i);

private:
    QBuffer *m_buffer = 0;
};

#endif // PACKSTREAM_H
