#pragma once

#include <set>
#include <map>
#include <thread>
#include <memory>

#include "pg_msg.h"

namespace ICE {
    class Candidate;
    class Media;
    class Agent;
    class CChannel;
    class CAgentConfig;

    class Session
    {
    public:
        Session();
        virtual ~Session();

        bool GatherCandidate(const CAgentConfig& config);

    private:
        static void GatheringThread(Session *pOwn, const CAgentConfig& config);

    private:
        using CChannelPtr                   = std::shared_ptr<CChannel>;
        using HostCandidateContainer        = std::map<Candidate*, Media*>;
        using SrflxCandidateContainer       = std::map<Candidate*, Media*>;
        using RelayedCandidateContainer     = std::map<Candidate*, Media*>;
        using PeerSrflxCandidateContainer   = std::map<Candidate*, Media*>;
        using MediaContainer                = std::set<Media*>; /* key: @string*/
        using ChannelContainer              = std::set<CChannelPtr>;

    private:
        std::thread m_gatherThrd;

        MediaContainer              m_Medias;
        HostCandidateContainer      m_HostCands;
        SrflxCandidateContainer     m_SrflxCands;
        RelayedCandidateContainer   m_RelayedCands;
        PeerSrflxCandidateContainer m_PeerSrflxCands;
    };
}