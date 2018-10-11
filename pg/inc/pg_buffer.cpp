#include "pg_buffer.h"

#include <memory>
#include <assert.h>


PG::circular_buffer::circular_buffer(int16_t size) noexcept :
    m_capacity(size),m_buffer(new uint8_t[size]), m_end(m_buffer + size),
    m_reader(m_buffer),m_writer(m_buffer),m_size(0)
{
}

PG::circular_buffer::~circular_buffer()
{
    delete m_buffer;
}

int PG::circular_buffer::write(const void * buf, int size)
{

    assert(buf && size);

    if (is_bad())
        return 0;

    std::lock_guard<std::mutex> locker(m_writer_mutex);

    int remain_bytes = m_capacity - m_size;
    if (remain_bytes == 0)
        return 0;

    int write_bytes = remain_bytes > size ? size : remain_bytes;

    bool bOverflow = false;

    {
        std::lock_guard<std::mutex> reader_locker(m_reader_mutex);
        bOverflow = (m_writer >= m_reader && (m_end - m_writer) < write_bytes);
    }

    if (bOverflow)
    {
        int to_end_bytes = m_end - m_writer;
        memcpy(m_writer, buf, m_end - m_writer);
        memcpy(m_buffer, (uint8_t*)buf + to_end_bytes, write_bytes - to_end_bytes);
        m_writer = m_buffer + write_bytes - to_end_bytes;
    }
    else
    {
        memcpy(m_writer, buf, write_bytes);
        m_writer += write_bytes;
    }

    m_size += write_bytes;
    return write_bytes;

    return 0;
}

int PG::circular_buffer::read(void * buf, int size)
{

    assert(buf && size);

    if (is_bad())
        return 0;

    std::lock_guard<std::mutex> locker(m_reader_mutex);
    if (!m_size)
        return 0;

    int read_bytes = m_size > size ? size : m_size;

    bool bOverflow = false;
    {
        std::lock_guard<std::mutex> writer_locker(m_writer_mutex);
        bOverflow = (m_reader >= m_writer && (m_end - m_reader) < read_bytes);
    }

    if (bOverflow)
    {
        int to_end_bytes = m_end - m_reader;
        memcpy(buf, m_reader, to_end_bytes);
        memcpy((uint8_t*)buf + to_end_bytes, m_buffer, read_bytes - to_end_bytes);
        m_reader = m_buffer + read_bytes - to_end_bytes;
    }
    else
    {
        memcpy(buf, m_reader, read_bytes);
        m_reader += read_bytes;
    }

    m_size -= read_bytes;
    return read_bytes;
}

int PG::circular_buffer::is_bad()
{
    return m_buffer == nullptr;
}
