#include "session.h"
#include "agent.h"
#include "media.h"
#include "channel.h"
#include "candidate.h"
#include "pg_log.h"


#include <assert.h>

namespace ICE {
    Session::Session()
    {
    }

    Session::~Session()
    {
    }

    bool Session::GatherCandidate(const CAgentConfig & config)
    {
       // m_gatherThrd = std::thread(this, config);
        return true;
    }

    void Session::GatheringThread(Session * pOwn, const CAgentConfig & agentConfig)
    {
        assert(pOwn);

        CAgentConfig cfg(agentConfig);

        assert(cfg.DefaultIP().length());
    }
}