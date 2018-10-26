
#include "media.h"
#include "channel.h"

namespace ICE {
    Stream::Stream(Channel_Ptr channel, int16_t maxPacketSize, int16_t cacheSize) :
        m_bQuit(false),m_MaxPacketSize(maxPacketSize)
    {
        //RegisterEvent(static_cast<uint16_t>(MsgId::sent));
        //RegisterEvent(static_cast<uint16_t>(MsgId::recv));

        m_RecvThrd = std::thread(Stream::SendThread, this);
        m_SendThrd = std::thread(Stream::RecvThread, this);
    }

    Stream::~Stream()
    {
        m_bQuit = true;
    }

    void Stream::SendThread(Stream* pOwn)
    {
        while (!pOwn->m_bQuit)
        {
        }
    }

    void Stream::RecvThread(Stream* pOwn)
    {
        assert(pOwn);

        while (!pOwn->m_bQuit)
        {
            auto size = pOwn->m_Channel->Read(0, pOwn->m_MaxPacketSize);
        }
    }
}