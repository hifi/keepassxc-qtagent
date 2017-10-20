#ifndef OPENSSHKEY_H
#define OPENSSHKEY_H

#include "BinaryStream.h"

namespace SSHAgent {
    class OpenSSHKey;
}

class OpenSSHKey
{
public:
    OpenSSHKey() { }
    OpenSSHKey(QString type, QList<QByteArray> data, QString comment) : m_type(type), m_privateData(data), m_comment(comment) { }

    QString getType();
    int getKeyLength();
    QString getFingerprint();
    QString getComment();

    void setType(QString type);
    void setPublicData(QList<QByteArray> data);
    void setPrivateData(QList<QByteArray> data);
    void setComment(QString comment);

    static QList<QSharedPointer<OpenSSHKey>> parse(QByteArray &data);

    bool readPublic(BinaryStream &stream);
    bool readPrivate(BinaryStream &stream);
    bool writePublic(BinaryStream &stream);
    bool writePrivate(BinaryStream &stream);
private:

    QString m_type;
    QList<QByteArray> m_publicData;
    QList<QByteArray> m_privateData;
    QString m_comment;
};

#endif // OPENSSHKEY_H
