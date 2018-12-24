#pragma once

#include <map>
#include <assert.h>

#include "streamdef.h"

namespace STUN {
    class Candidate;
}

namespace ICE {
    class CAgentConfig;
    class Media;
    class Session
    {
    public:
        class SessionConfig {
        public:
            SessionConfig(uint64_t tiebreak, const std::string& defaultIP) :
                m_Tiebreaker(tiebreak),
                m_DefaultIP(defaultIP),
                m_Username("-"),
                m_SessionName("-")
            {
            }

            ~SessionConfig()
            {
            }

        public:
            const std::string GetConnectivityCheckUsername() const
            {
                return m_RemoteUserFrag + ":";
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

            const std::string& UserName() const
            {
                return m_Username;
            }

            const std::string& SessionName() const
            {
                return m_SessionName;
            }

            const std::string& DefaultIP() const
            {
                return m_DefaultIP;
            }

            bool IsControlling() const { return m_bControlling; }

        private:
            /* rfc5245 15.4 */
            std::string m_RemoteUserFrag;
            std::string m_RemoteUserPwd;

            const std::string m_Username;    /*for SDP*/
            const std::string m_SessionName; /*for SDP*/
            const std::string m_DefaultIP;

            bool m_bControlling;
            const uint64_t m_Tiebreaker; /* rfc8445 16.1 */
        };

    public:
        class CandidatePeer {
        public:
            CandidatePeer(uint64_t PRI, const STUN::Candidate* lcand, const STUN::Candidate* rcand);
            virtual ~CandidatePeer();

            void Priority(uint64_t pri) { m_PRI = pri; }
            uint64_t Priority() const { return m_PRI; }

            void LCandidate(const STUN::Candidate* lcand) { assert(lcand); m_LCand = lcand; }
            const STUN::Candidate& LCandidate() const { assert(m_LCand); return *m_LCand; }

            void RCandidate(const STUN::Candidate* rcand) { assert(rcand); m_RCand = rcand; }
            const STUN::Candidate& RCandidate() const { assert(m_RCand); return *m_RCand; }

        private:
            uint64_t m_PRI;
            const STUN::Candidate *m_LCand;
            const STUN::Candidate *m_RCand;
        };

    public:
        using CandPeerContainer = std::map<uint64_t, CandidatePeer>;/*@uint32_t : PRI*/
        using MediaContainer = std::map<std::string, const Media*>;
        using MediaCandPairs = std::map<std::string, CandPeerContainer*>;

    public:
        Session(const std::string& defaultIP);
        virtual ~Session();

        bool CreateMedia(const MediaAttr& mediaAttr, const CAgentConfig& config);
        bool ConnectivityCheck(const std::string& offer);
        bool MakeOffer(std::string& offer);
        bool MakeAnswer(const std::string& remoteOffer, std::string& answer);
        const MediaContainer& GetMedias() const { return m_Medias; }
        const SessionConfig& Config() const { return m_Config; }

    private:
        SessionConfig           m_Config;
        MediaContainer          m_Medias;
        MediaCandPairs          m_MediaCandPairs;
    };
}