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
    OpenSSHKey(QString type, QList<QByteArray> data, QString comment) : m_type(type), m_data(data), m_comment(comment) { }

    void setType(QString type);
    void setData(QList<QByteArray> data);
    void setComment(QString comment);

    static QList<QSharedPointer<OpenSSHKey>> parse(QByteArray &data);

    bool fromStream(BinaryStream &stream);
    bool toStream(BinaryStream &stream);
private:

    QString m_type;
    QList<QByteArray> m_data;
    QString m_comment;
};

#endif // OPENSSHKEY_H
