#pragma once

#include <vector>
#include <condition_variable>
#include <mutex>

namespace PG {
    class circular_buffer {
    public:
        circular_buffer(int16_t size) noexcept;
        virtual ~circular_buffer();

        int write(const void *buf, int size);
        int read(void *buf, int size);
        int is_bad();

    private:
        mutable std::mutex m_mutex;

        uint8_t* const m_buffer;
        uint8_t* const m_end;

        uint8_t *m_reader;
        uint8_t *m_writer;
        int16_t m_size;

        const int16_t m_capacity;
    };
}
