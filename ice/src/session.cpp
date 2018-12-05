#include "session.h"
#include "agent.h"
#include "media.h"
#include "channel.h"
#include "candidate.h"
#include "pg_log.h"

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>

#include <assert.h>

namespace {
    static const char BASE64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    static const uint16_t BASE64_CNT = sizeof(BASE64) / sizeof(BASE64[0]);

    std::string GenerateUserFrag()
    {
        std::string frag;
        for (uint16_t i = 0; i < STUN::sIceUfragLength; ++i)
            frag += BASE64[PG::GenerateRandom(0, BASE64_CNT - 1)];
        return frag;
    }

    std::string GenerateUserPwd()
    {
        std::string pwd;
        for (uint16_t i = 0; i < STUN::sIcePWDLength; ++i)
            pwd += BASE64[PG::GenerateRandom(0, BASE64_CNT - 1)];
        return pwd;
    }
}

namespace ICE {
    Session::Session() :
        m_Config(PG::GenerateRandom64(), GenerateUserFrag(), GenerateUserPwd())
    {
    }

    Session::~Session()
    {
    }

    bool Session::GatherCandidate(const CAgentConfig & config)
    {
        return true;
    }

    void Session::GatheringThread(Session * pOwn, const CAgentConfig & agentConfig)
    {
        assert(pOwn);

        CAgentConfig cfg(agentConfig);
        assert(cfg.DefaultIP().length());
    }
}