#ifndef IDENTITY_H
#define IDENTITY_H

#include <QtCore>

namespace SSHAgent {
    class Identity;
}

class Identity
{
    const quint8 TAG_INT        = 0x02;
    const quint8 TAG_SEQUENCE   = 0x30;

    const quint8 KEY_RSA        = 0x0;

public:
    Identity(QIODevice& dev) : Identity(dev.readAll()) { }
    Identity(QByteArray& ba) : Identity(QString::fromUtf8(ba)) { }
    Identity(QString pem) : m_pem(pem) { }

    bool parse();
    QByteArray toWireFormat();
private:
    bool nextTag(QDataStream &stream, quint8 &tag, quint32 &len);
    bool readInt(QDataStream &stream, QByteArray &target);
    bool parseDer(QByteArray der);

    QString m_pem;

    QByteArray m_n;
    QByteArray m_e;
    QByteArray m_d;
    QByteArray m_p;
    QByteArray m_q;
    QByteArray m_dp;
    QByteArray m_dq;
    QByteArray m_qinv;
};

#endif // IDENTITY_H
