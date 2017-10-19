#ifndef PEM_H
#define PEM_H

#include "Identity.h"

#include <QtCore>

class PEM
{
public:
    PEM(QIODevice& dev) : PEM(dev.readAll()) { }
    PEM(QByteArray& ba) : PEM(QString::fromUtf8(ba)) { }
    PEM(QString s) : m_string(s) { }

    bool parse();
    QString getType();
    Identity* getIdentity();

private:
    QString m_string;
    QString m_type;
    QByteArray m_data;
};

#endif // PEM_H
