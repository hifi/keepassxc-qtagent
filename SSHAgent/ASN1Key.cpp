#include "ASN1Key.h"

#include <gcrypt.h>

QList<QSharedPointer<OpenSSHKey>> ASN1Key::parseDSA(QByteArray &ba)
{
    QList<QSharedPointer<OpenSSHKey>> keyList;

    BinaryStream stream(&ba);

    if (!parseHeader(stream, KEY_ZERO)) {
        return keyList;
    }

    QByteArray p,q,g,y,x;
    readInt(stream, p);
    readInt(stream, q);
    readInt(stream, g);
    readInt(stream, y);
    readInt(stream, x);

    QList<QByteArray> data;
    data.append(p);
    data.append(q);
    data.append(g);
    data.append(y);
    data.append(x);

    OpenSSHKey *key = new OpenSSHKey();
    key->setType("ssh-dss");
    key->setData(data);
    key->setComment("id_dsa");
    keyList.append(QSharedPointer<OpenSSHKey>(key));

    return keyList;
}

QList<QSharedPointer<OpenSSHKey>> ASN1Key::parseRSA(QByteArray &ba)
{
    QList<QSharedPointer<OpenSSHKey>> keyList;

    BinaryStream stream(&ba);

    if (!parseHeader(stream, KEY_ZERO)) {
        return keyList;
    }

    QByteArray n,e,d,p,q,dp,dq,qinv;
    readInt(stream, n);
    readInt(stream, e);
    readInt(stream, d);
    readInt(stream, p);
    readInt(stream, q);
    readInt(stream, dp);
    readInt(stream, dq);
    readInt(stream, qinv);

    QList<QByteArray> data;
    data.append(n);
    data.append(e);
    data.append(d);
    data.append(calculateIqmp(p, q));
    data.append(p);
    data.append(q);

    OpenSSHKey *key = new OpenSSHKey();
    key->setType("ssh-rsa");
    key->setData(data);
    key->setComment("id_rsa");
    keyList.append(QSharedPointer<OpenSSHKey>(key));

    return keyList;
}

bool ASN1Key::parseHeader(BinaryStream &stream, quint8 wantedType)
{
    quint8 tag;
    quint32 len;

    nextTag(stream, tag, len);

    if (tag != TAG_SEQUENCE) {
        return false;
    }

    nextTag(stream, tag, len);

    if (tag != TAG_INT || len != 1) {
        return false;
    }

    quint8 keyType;
    stream.read(keyType);

    return (keyType == wantedType);
}

QByteArray ASN1Key::calculateIqmp(QByteArray &bap, QByteArray &baq)
{
    gcry_mpi_t u, p, q;
    QByteArray iqmp_hex;

    u = gcry_mpi_snew(bap.length() * 8);
    gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, bap.toHex().data(), 0, NULL);
    gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, baq.toHex().data(), 0, NULL);

    mpi_invm(u, q, p);

    iqmp_hex.resize((bap.length() + 1) * 2);
    gcry_mpi_print(GCRYMPI_FMT_HEX, (unsigned char *)iqmp_hex.data(), iqmp_hex.length(), NULL, u);

    gcry_mpi_release(u);
    gcry_mpi_release(p);
    gcry_mpi_release(q);

    return QByteArray::fromHex(iqmp_hex);
}

bool ASN1Key::nextTag(BinaryStream &stream, quint8 &tag, quint32 &len)
{
    stream.read(tag);

    quint8 lenByte;
    stream.read(lenByte);

    if (lenByte & 0x80) {
        quint32 bytes = lenByte & ~0x80;
        if (bytes == 1) {
            stream.read(lenByte);
            len = lenByte;
        } else if (bytes == 2) {
            quint16 lenShort;
            stream.read(lenShort);
            len = lenShort;
        } else if (bytes == 4) {
            stream.read(len);
        } else {
            qWarning() << "ASN.1 tag length is" << bytes << "bytes";
            return false;
        }
    } else {
        len = lenByte;
    }

    return true;
}

bool ASN1Key::readInt(BinaryStream &stream, QByteArray &target)
{
    quint8 tag;
    quint32 len;

    nextTag(stream, tag, len);

    if (tag != ASN1Key::TAG_INT)
        return false;

    target.resize(len);
    stream.read(target);
    return true;
}
