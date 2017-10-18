#ifndef BINARYSTREAM_H
#define BINARYSTREAM_H

#include <QObject>
#include <QIODevice>
#include <QBuffer>

class BinaryStream : public QObject
{
    Q_OBJECT
public:
    explicit BinaryStream(QObject *parent = 0) : QObject(parent) { }
    BinaryStream(QIODevice *dev, QObject *parent = 0) : QObject(parent), m_dev(dev) { }
    BinaryStream(QByteArray *ba, QObject *parent = 0);
    ~BinaryStream();

    const QString errorString();
    QIODevice* getDevice();
    void setDevice(QIODevice *dev);
    void setTimeout(int timeout);

    bool read(QByteArray &ba);
    bool read(quint32 &i);
    bool read(quint8 &i);

    bool write(const QByteArray &ba);
    bool write(quint32 i);
    bool write(quint8 i);

    bool flush();

signals:

public slots:

protected:
    bool read(char *ptr, qint64 len);
    bool write(const char *ptr, qint64 len);

private:
    int m_timeout = -1;
    QString m_error;
    QIODevice *m_dev = 0;
    QBuffer *m_buffer = 0;
};

#endif // BINARYSTREAM_H
