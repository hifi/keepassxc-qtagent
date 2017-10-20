#ifndef ASN1KEY_H
#define ASN1KEY_H

#include "OpenSSHKey.h"
#include <QtCore>

namespace SSHAgent {
    class ASN1Key;
}

class ASN1Key
{
public:
    static QList<QSharedPointer<OpenSSHKey>> parseDSA(QByteArray &ba);
    static QList<QSharedPointer<OpenSSHKey>> parseRSA(QByteArray &ba);

private:
    static const quint8 TAG_INT        = 0x02;
    static const quint8 TAG_SEQUENCE   = 0x30;
    static const quint8 KEY_ZERO       = 0x0;

    ASN1Key() { }
    static QByteArray calculateIqmp(QByteArray &p, QByteArray &q);

    static bool nextTag(BinaryStream &stream, quint8 &tag, quint32 &len);
    static bool readInt(BinaryStream &stream, QByteArray &target);
};

#endif // ASN1KEY_H
