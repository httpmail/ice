#pragma once

#include <map>
#include "pg_msg.h"
#include "media.h"

namespace ICE {

    class Candidate;

    class Session
    {
    public:
        class SessionConfig {
        public:
            SessionConfig(uint64_t tiebreak) :
                m_Tiebreaker(tiebreak),
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

        private:
            /* rfc5245 15.4 */
            std::string m_RemoteUserFrag;
            std::string m_RemoteUserPwd;

            const std::string m_Username;  /*for SDP*/
            const std::string m_SessionName; /*for SDP*/

            bool m_bControlling;
            const uint64_t m_Tiebreaker; /* rfc8445 16.1 */
        };

        class RemoteMedia {
        public:
            using CandContainer = std::set<Candidate*>;

        public:
            RemoteMedia();
            virtual ~RemoteMedia();

            void AddHostCandidate(uint8_t compId, bool bUDP, const std::string& baseIP, uint16_t basePort);

            void AddSrflxCandidate(uint8_t compId, bool bUDP,
                const std::string& baseIP, uint16_t basePort,
                const std::string& relatedIP, uint16_t relatedPort);

            void AddPrflxCandidate(uint8_t compId, bool bUDP,
                const std::string& baseIP, uint16_t basePort,
                const std::string& relatedIP, uint16_t relatedPort);

            void AddRelayCandidate(uint8_t compId, bool bUDP,
                const std::string& baseIP, uint16_t basePort,
                const std::string& relatedIP, uint16_t relatedPort);

        private:
            const std::string   m_icepwd;
            const std::string   m_iceufrag;
            CandContainer       m_Cands;
        };

    public:
        Session();
        virtual ~Session();

        bool MakeOffer(std::string& offer);
        bool MakeAnswer(const std::string& remoteOffer, std::string& answer);
        bool DecodeSDP(const std::string& offer);

    private:
        bool DecodeMediaLine(const std::string& mediaLine, bool bUfragPwdExisted);

    private:
        using MediaContainer        = std::map<std::string, Media*>;
        using RemoteMediaContainer  = std::map<std::string, RemoteMedia*>;

    private:
        SessionConfig           m_Config;
        MediaContainer          m_Medias;
        RemoteMediaContainer    m_RemoteMedias;
        std::string             m_DefaultIP;
    };
}