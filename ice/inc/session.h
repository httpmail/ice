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
        class SessionConfig {
        public:
            SessionConfig(uint64_t tiebreak, const std::string& localFrag, const std::string& localPwd) :
                m_Tiebreaker(tiebreak), m_LocalUserFrag(localFrag), m_LocalUserPwd(localPwd)
            {
            }

            ~SessionConfig()
            {
            }

        public:
            const std::string GetConnectivityCheckUsername() const
            {
                return m_RemoteUserFrag + ":" + m_LocalUserFrag;
            }

            const std::string GetConnectivityCheckPassword() const
            {
                return m_RemoteUserPwd;
            }

            void RemoteUserFrag(const std::string& remoteUserFrag)
            {
                m_RemoteUserFrag = remoteUserFrag;
            }
            const std::string& RemoteUserFrag() const
            {
                return m_RemoteUserFrag;
            }

            void RemoteUserPassword(const std::string& remoteUserPwd)
            {
                m_RemoteUserPwd = remoteUserPwd;
            }
            const std::string& RemoteUserPassword() const
            {
                return m_RemoteUserPwd;
            }

        private:
            /* rfc5245 15.4 */
            std::string m_LocalUserFrag;
            std::string m_LocalUserPwd;
            std::string m_RemoteUserFrag;
            std::string m_RemoteUserPwd;

            bool m_bControlling;
            const uint64_t m_Tiebreaker; /* rfc8445 16.1 */
        };

    public:
        Session();
        virtual ~Session();

        bool GatherCandidate(const CAgentConfig& config);
        bool ConnectivityCheck();

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
        SessionConfig m_Config;
        MediaContainer              m_Medias;
        HostCandidateContainer      m_HostCands;
        SrflxCandidateContainer     m_SrflxCands;
        RelayedCandidateContainer   m_RelayedCands;
        PeerSrflxCandidateContainer m_PeerSrflxCands;
    };
}