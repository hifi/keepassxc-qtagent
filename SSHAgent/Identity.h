#ifndef IDENTITY_H
#define IDENTITY_H

#include <QtCore>

namespace SSHAgent {
    class Identity;
}

class Identity
{
public:
    virtual QByteArray toWireFormat() = 0;
};

#endif // IDENTITY_H
