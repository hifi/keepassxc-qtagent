#include "PEM.h"
#include "BinaryStream.h"
#include "RSAKey.h"
#include "OpenSSHKey.h"

bool PEM::parse()
{
    QStringList rows = m_string.split(QRegExp("[\r\n]"), QString::SkipEmptyParts);

    QString begin = rows.first();
    QString end = rows.last();

    QRegExp beginEx("-----BEGIN (.+)-----");
    QRegExp endEx("-----END (.+)-----");

    if (!beginEx.exactMatch(begin) || !endEx.exactMatch(end))
        return false;

    if (beginEx.cap(1) != endEx.cap(1))
        return false;

    m_type = beginEx.cap(1);

    rows.removeFirst();
    rows.removeLast();

    m_data = QByteArray::fromBase64(rows.join("").toLatin1());

    return (m_data.length() > 0);
}

QString PEM::getType()
{
    return m_type;
}

QList<QSharedPointer<OpenSSHKey>> PEM::getKeys()
{
    if (m_type == "RSA PRIVATE KEY") {
        return RSAKey::parse(m_data);
    } else if (m_type == "OPENSSH PRIVATE KEY") {
        return OpenSSHKey::parse(m_data);
    }

    QList<QSharedPointer<OpenSSHKey>> noKeys;
    return noKeys;
}
