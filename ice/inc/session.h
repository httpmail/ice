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
        std::string m_LocalUserFrag;
        std::string m_LocalPassword;
        std::string m_RemoteUserFrag;
        std::string m_RemotePassword;
        /*
        An ICE agent MUST use the same number for
        all Binding requests, for all streams, within an ICE session, unless
        it has received a 487 response, in which case it MUST change the
        number (Section 7.2.5.1).  The agent MAY change the number when an
        ICE restart occurs.*/
        uint64_t    m_Tiebreaker;
        bool        m_bControlling;

        MediaContainer              m_Medias;
        HostCandidateContainer      m_HostCands;
        SrflxCandidateContainer     m_SrflxCands;
        RelayedCandidateContainer   m_RelayedCands;
        PeerSrflxCandidateContainer m_PeerSrflxCands;
    };
}