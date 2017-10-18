#include "PackStream.h"
#include <QBuffer>

bool PackStream::read(QByteArray &ba)
{
   quint32 length;

   if (!BinaryStream::read(length))
       return false;

   ba.resize(length);

   if (!BinaryStream::read(ba.data(), ba.length()))
       return false;

   return true;
}

bool PackStream::read(QString &str)
{
    QByteArray ba;

    if (!read(ba))
        return false;

    str = str.fromLatin1(ba);
    return true;
}

bool PackStream::write(const QByteArray &ba)
{
    if (!BinaryStream::write((quint32) ba.length()))
        return false;
    if (!BinaryStream::write(ba))
        return false;

    return true;
}

bool PackStream::write(const QString &s)
{
    return write(s.toLatin1());
}

bool PackStream::write(quint8 i)
{
    if (!BinaryStream::write((quint32) sizeof(i)))
        return false;
    if (!BinaryStream::write(i))
        return false;

    return true;
}
