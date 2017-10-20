#ifndef RSAKEY_H
#define RSAKEY_H

#include "OpenSSHKey.h"
#include <QtCore>

namespace SSHAgent {
    class RSAKey;
}

class RSAKey
{
public:
    static QList<QSharedPointer<OpenSSHKey>> parse(QByteArray &ba);

private:
    static const quint8 TAG_INT        = 0x02;
    static const quint8 TAG_SEQUENCE   = 0x30;
    static const quint8 KEY_RSA        = 0x0;

    RSAKey() { }
    static QByteArray calculateIqmp(QByteArray &p, QByteArray &q);

    static bool nextTag(BinaryStream &stream, quint8 &tag, quint32 &len);
    static bool readInt(BinaryStream &stream, QByteArray &target);
};

#endif // RSAKEY_H
