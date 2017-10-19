#include "OpenSSHKey.h"
#include <QDebug>

void OpenSSHKey::setType(QString type)
{
    m_type = type;
}

void OpenSSHKey::setData(QList<QByteArray> data)
{
    m_data = data;
}

void OpenSSHKey::setComment(QString comment)
{
    m_comment = comment;
}

QList<QSharedPointer<OpenSSHKey>> OpenSSHKey::parse(QByteArray &data)
{
    QList<QSharedPointer<OpenSSHKey>> sshKeys;
    QByteArray magic;
    QString cipherName;
    QString kdfName;
    QString kdfOptions;
    quint32 numberOfKeys;
    QByteArray publicKey;
    QByteArray privateKeys;

    BinaryStream stream(&data);

    magic.resize(15);
    stream.read(magic);

    if (QString::fromLatin1(magic) != "openssh-key-v1") {
        qWarning() << "magic" << magic;
        return sshKeys;
    }

    stream.readPack(cipherName);

    if (cipherName != "none") {
        qWarning() << "cipherName" << cipherName;
        return sshKeys;
    }

    stream.readPack(kdfName);

    if (kdfName != "none") {
        qWarning() << "kdfName" << cipherName;
        return sshKeys;
    }

    stream.readPack(kdfOptions);
    stream.read(numberOfKeys);

    for (quint32 i = 0; i < numberOfKeys; i++) {
        publicKey.resize(0);
        stream.readPack(publicKey);
    }

    // padded list of keys
    stream.readPack(privateKeys);

    BinaryStream keyStream(&privateKeys);

    quint32 checkInt1;
    quint32 checkInt2;

    keyStream.read(checkInt1);
    keyStream.read(checkInt2);

    if (checkInt1 != checkInt2) {
        qWarning() << "check integers don't match";
        return sshKeys;
    }

    for (quint32 i = 0; i < numberOfKeys; i++) {
        OpenSSHKey *key = new OpenSSHKey();
        key->fromStream(keyStream);
        sshKeys.append(QSharedPointer<OpenSSHKey>(key));
    }

    return sshKeys;
}

bool OpenSSHKey::fromStream(BinaryStream &stream)
{
    m_data.clear();
    stream.readPack(m_type);

    if (m_type == "ssh-rsa") {
        for (int i = 0; i < 6; i++) {
            QByteArray t;
            stream.readPack(t);
            m_data.append(t);
        }
    } else if (m_type == "ssh-ed25519") {
        for (int i = 0; i < 2; i++) {
            QByteArray t;
            stream.readPack(t);
            m_data.append(t);
        }
    } else {
        qWarning() << "Unknown OpenSSH key type" << m_type;
        return false;
    }

    stream.readPack(m_comment);
    return true;
}

bool OpenSSHKey::toStream(BinaryStream &stream)
{
    stream.writePack(m_type);

    foreach (QByteArray t, m_data) {
        stream.writePack(t);
    }

    stream.writePack(m_comment);
    return true;
}
