#pragma once

#include <stdint.h>
#include <unordered_set>
#include <atomic>
#include <assert.h>
#include "pg_msg.h"

namespace STUN {
    class Candidate;
    class HostCandidate;
    class ActiveCandidate;
    class PassiveCandidate;
    class SrflxCandidate;
}

namespace ICE {
    class CAgentConfig;

    class Stream : PG::MsgEntity{
    public:
        static const uint8_t RTP_ID     = 1;
        static const uint8_t RTCP_ID    = 2;

    public:
        enum  class Pipline
        {
            udp,
            passive_tcp,
            active_tcp,
        };

        enum class Message {
            Gathering,
            Checking,
        };

    public:
        Stream(uint8_t compId, Pipline pipline, const std::string& hostIp, uint16_t hostPort = 0) :
            m_CompId(compId), m_Pipline(pipline), m_HostIP(hostIp), m_HostPort(hostPort),m_State(State::Init),m_Quit(false)
        {
            RegisterEvent(static_cast<PG::MsgEntity::MSG_ID>(Message::Gathering));
            RegisterEvent(static_cast<PG::MsgEntity::MSG_ID>(Message::Checking));
        }

        virtual ~Stream();
        bool Create(const CAgentConfig& config);

    private:
        enum class State : uint8_t{
            Init,
            Creating,
            CreateFailed,
            CreateDone,
            Checking,
            CheckFailed,
            CheckingDone
        };

    protected:
        using CandidateContainer = std::unordered_set<STUN::Candidate*>;

        static void GatheringCandidate(Stream* pThis, const CAgentConfig& config);
        static void CheckConnectivity(Stream* pThis);

    private:
        const uint8_t       m_CompId;
        const Pipline       m_Pipline;
        const std::string   m_HostIP;
        const int16_t       m_HostPort;
        std::thread         m_GatherThrd;
        std::mutex          m_CandsMutex;
        CandidateContainer  m_Cands;
        std::atomic<State>  m_State;
        std::atomic_bool    m_Quit;
    };
}