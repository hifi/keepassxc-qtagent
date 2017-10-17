#include "Identity.h"
#include <gcrypt.h>

bool Identity::parse()
{
    QStringList rows = m_pem.split(QRegExp("[\r\n]"), QString::SkipEmptyParts);

    QString begin = rows.first();
    QString end = rows.last();

    if (!begin.startsWith("-----BEGIN") || !end.startsWith("-----END"))
        return false;

    rows.removeFirst();
    rows.removeLast();

    QByteArray data = QByteArray::fromBase64(rows.join("").toLatin1());

    return parseDer(data);
}

bool Identity::nextTag(QDataStream &stream, quint8 &tag, quint32 &len)
{
    stream >> tag;

    quint8 lenByte;
    stream >> lenByte;

    if (lenByte & 0x80) {
        quint32 bytes = lenByte & ~0x80;
        if (bytes == 1) {
            stream >> lenByte;
            len = lenByte;
        } else if (bytes == 2) {
            quint16 lenShort;
            stream >> lenShort;
            len = lenShort;
        } else if (bytes == 4) {
            stream >> len;
        } else {
            qWarning() << "ASN.1 tag length is" << bytes << "bytes";
            return false;
        }
    } else {
        len = lenByte;
    }

    return true;
}

bool Identity::readInt(QDataStream &stream, QByteArray &target)
{
    quint8 tag;
    quint32 len;

    nextTag(stream, tag, len);

    if (tag != TAG_INT)
        return false;

    target.resize(len);
    stream.readRawData(target.data(), len);
}

bool Identity::parseDer(QByteArray der)
{
    quint8 tag;
    quint32 len;

    QDataStream stream(der);

    nextTag(stream, tag, len);

    if (tag != TAG_SEQUENCE)
        return false;

    nextTag(stream, tag, len);

    if (tag != TAG_INT || len != 1)
        return false;

    quint8 keyType;
    stream >> keyType;

    if (keyType != KEY_RSA)
        return false;

    readInt(stream, m_n);
    readInt(stream, m_e);
    readInt(stream, m_d);
    readInt(stream, m_p);
    readInt(stream, m_q);
    readInt(stream, m_dp);
    readInt(stream, m_dq);
    readInt(stream, m_qinv);
}

QByteArray Identity::toWireFormat()
{
    gcry_mpi_t u, p, q;

    QByteArray ba;
    QDataStream stream(&ba, QIODevice::WriteOnly);

    char keyType[] = { 's', 's', 'h', '-', 'r', 's', 'a' };
    QByteArray tmp(keyType);

    //stream << (quint32) sizeof(keyType);
    stream << tmp;
    //stream << (quint32)m_n.length();
    stream << m_n;
    //stream << (quint32)m_e.length();
    stream << m_e;
    //stream << (quint32)m_d.length();
    stream << m_d;

    gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, m_p.toHex().data(), 0, NULL);
    gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, m_q.toHex().data(), 0, NULL);

    u = gcry_mpi_snew(m_p.length() * 8);
    mpi_invm(u, q, p);

    QByteArray iqmp_hex;
    iqmp_hex.resize((m_p.length() + 1) * 2);

    gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char *)iqmp_hex.data(), iqmp_hex.length(), NULL, u);

    QByteArray iqmp = QByteArray::fromHex(iqmp_hex);

    //stream << (quint32)iqmp.length();
    stream << iqmp;

    //stream << (quint32)m_p.length();
    stream << m_p;
    //stream << (quint32)m_q.length();
    stream << m_q;

    return ba;
}
