#pragma once

#include <vector>
#include <unordered_set>
#include <condition_variable>
#include <mutex>
#include <atomic>
#include <assert.h>

namespace PG {
    class circular_buffer {
    public:
        circular_buffer(int16_t size) noexcept;
        virtual ~circular_buffer();

        int write(const void *buf, int size);
        int read(void *buf, int size);
        int is_bad();

    private:
        mutable std::mutex m_writer_mutex;
        mutable std::mutex m_reader_mutex;

        uint8_t* const m_buffer;
        uint8_t* const m_end;

        uint8_t *m_reader;
        uint8_t *m_writer;
        int16_t m_size;

        const int16_t m_capacity;
    };

    template<class packet_type, uint16_t MAX_SIZE>
    class PacketBuffer {
    private:
        using PacketContainer = std::vector<packet_type*>;

    public:
        class PacketGuard {
            PacketGuard(packet_type* packet, PacketContainer& recycleContainer, std::mutex &mutex, std::condition_variable &cond) :
                m_packet(packet), m_recycleCon(recycleContainer), m_mutex(mutex), m_cond(cond), m_isNull(packet == nullptr)
            {
            }

        public:
            PacketGuard(const PacketGuard& other)
                :PacketGuard(other.m_packet, other.m_mutex, other.m_recycleCon, other.m_cond)
            {
                other.m_packet = nullptr;
            }

            bool IsNull() const { return m_isNull;}

            ~PacketGuard()
            {
                std::lock_guard<std::mutex> locker(m_mutex);
                if (m_packet)
                {
                    m_recycleCon.push_back(m_packet);
                    m_cond.notify_all();
                }
            }

            packet_type* operator->() { assert(m_isNull);  return m_packet; }
            const packet_type* operator->() const { assert(m_isNull); return m_packet; }

        private:
            packet_type     *m_packet;
            PacketContainer &m_recycleCon;
            std::mutex      &m_mutex;
            std::condition_variable &m_cond;
            bool             m_isNull;

            friend class PacketBuffer<packet_type, MAX_SIZE>;
        };

    public:
        PacketBuffer() 
        {
            static_assert(MAX_SIZE, "buffer_size MUST > 0");
            static_assert(!std::is_pointer<packet_type>::value, "packet_type cannot be pointer");
            static_assert(std::is_class<packet_type>::value, "packet_type MUST be a class or struct");

            m_FreePacket.reserve(MAX_SIZE);
            m_ReadyPacket.reserve(MAX_SIZE);

            for (int i = 0; i < MAX_SIZE; ++i)
                m_FreePacket.push_back(&m_Packet[i]);
        }

        virtual ~PacketBuffer()
        {
        }

        PacketBuffer(const PacketBuffer&) = delete;

        PacketGuard GetFreePacket()
        {
            std::lock_guard<std::mutex> locker(m_FreePacketMutex);
            if (m_FreePacket.size())
            {
                auto packet = *m_FreePacket.begin();
                m_FreePacket.erase(m_FreePacket.begin());
                return PacketGuard(packet, m_ReadyPacket,m_ReadyPacketMutex, m_ReadyCondition);
            }
            return PacketGuard(nullptr, m_ReadyPacket, m_ReadyPacketMutex, m_ReadyCondition);
        }

        PacketGuard GetReadyPacket()
        {
            std::lock_guard<std::mutex> locker(m_ReadyPacketMutex);
            if (m_ReadyPacket.size())
            {
                auto packet = *m_ReadyPacket.begin();
                m_ReadyPacket.erase(m_ReadyPacket.begin());
                return PacketGuard(packet, m_FreePacket, m_FreePacketMutex, m_FreeCondition);
            }
            return PacketGuard(nullptr, m_FreePacket, m_FreePacketMutex, m_FreeCondition);
        }

        PacketGuard WaitFreePacket()
        {
            std::unique_lock<std::mutex> locker(m_FreePacketMutex);
            m_FreeCondition.wait(locker, [this] {
                return !this->m_FreePacket.empty();
            });

            auto packet = *m_FreePacket.begin();
            m_FreePacket.erase(m_FreePacket.begin());
            return PacketGuard(packet, m_ReadyPacket, m_ReadyPacketMutex, m_ReadyCondition);
        }

        PacketGuard WaitReadyPacket()
        {
            std::unique_lock<std::mutex> locker(m_ReadyPacketMutex);
            m_ReadyCondition.wait(locker, [this] {
                return !this->m_ReadyPacket.empty();
            });

            auto packet = *m_ReadyPacket.begin();
            m_ReadyPacket.erase(m_ReadyPacket.begin());
            return PacketGuard(packet, m_FreePacket, m_FreePacketMutex, m_FreeCondition);
        }

        template<class _Rep, class _Period, class _Predicate>
        bool WaitForFreePacket(const std::chrono::duration<_Rep, _Period>& _Rel_time, _Predicate _Pred)
        {
            std::unique_lock<std::mutex> locker(m_FreePacketMutex);
            return m_FreeCondition.wait_for(locker, _Rel_time, _Pred);
        }

        template<class _Rep, class _Period, class _Predicate>
        bool WaitForReadyPacket(const std::chrono::duration<_Rep, _Period>& _Rel_time, _Predicate _Pred)
        {
            std::unique_lock<std::mutex> locker(m_ReadyPacketMutex);
            return m_ReadyCondition.wait_for(locker, _Rel_time, _Pred);
        }

    protected:
        std::mutex              m_FreePacketMutex;
        std::mutex              m_ReadyPacketMutex;
        std::condition_variable m_FreeCondition;
        std::condition_variable m_ReadyCondition;

        PacketContainer m_FreePacket;
        PacketContainer m_ReadyPacket;
        packet_type     m_Packet[MAX_SIZE];
    };
}
