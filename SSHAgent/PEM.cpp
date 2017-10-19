#include "PEM.h"
#include "RSAKey.h"

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

Identity* PEM::getIdentity()
{
    if (m_type == "RSA PRIVATE KEY") {
        return RSAKey::fromDer(m_data);
    }

    return Q_NULLPTR;
}
