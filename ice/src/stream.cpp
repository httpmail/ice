#include "stream.h"
#include "candidate.h"
#include "agent.h"

namespace ICE {

    Stream::~Stream()
    {
    }

    bool Stream::Create(const CAgentConfig& config)
    {
        if (m_State.load() != State::Init)
        {
            LOG_ERROR("Stream", "CreateStream only work on Init state, current[%d]", m_State);
            return false;
        }

        m_GatherThrd = std::thread(Stream::GatheringCandidate, this, config);
        return true;
    }

    void Stream::GatheringCandidate(Stream * pThis, const CAgentConfig& config)
    {
    }
}
