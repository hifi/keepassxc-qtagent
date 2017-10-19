#ifndef RSAKEY_H
#define RSAKEY_H

#include "Identity.h"

#include <QtCore>

namespace SSHAgent {
    class RSAKey;
}

class RSAKey : public Identity
{
public:
    RSAKey();
    static RSAKey* fromDer(QByteArray der);
    virtual QByteArray toWireFormat();

private:
    static const quint8 TAG_INT        = 0x02;
    static const quint8 TAG_SEQUENCE   = 0x30;

    static const quint8 KEY_RSA        = 0x0;

    static bool nextTag(QDataStream &stream, quint8 &tag, quint32 &len);
    static bool readInt(QDataStream &stream, QByteArray &target);

    QByteArray m_n;
    QByteArray m_e;
    QByteArray m_d;
    QByteArray m_p;
    QByteArray m_q;
    QByteArray m_dp;
    QByteArray m_dq;
    QByteArray m_qinv;
    QByteArray m_iqmp;
};

#endif // RSAKEY_H
