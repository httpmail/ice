#pragma once

#include <stdint.h>
#include <string>
#include <memory>
#include <unordered_map>

#include "pg_msg.h"
#include "pg_buffer.h"

namespace ICE {

    class CChannel;
    class Stream {
    protected:
        using Channel_Ptr = std::shared_ptr<CChannel>;

    public:
        enum class MsgId : uint16_t {
            sent,
            recv,
        };

    public:
        Stream(Channel_Ptr channel, int16_t maxPacketSize, int16_t cacheSize);
        virtual ~Stream() = 0;

        virtual int16_t send(const char* buf, int16_t size) = 0;
        virtual int16_t recv(char *buf, int16_t size) = 0;

    private:
        static void RecvThread(Stream *pOwn);
        static void SendThread(Stream *pOwn);

    protected:
        std::thread         m_SendThrd;
        std::thread         m_RecvThrd;
        bool                m_bQuit;
        Channel_Ptr         m_Channel;
        const int16_t       m_MaxPacketSize;
    };
}