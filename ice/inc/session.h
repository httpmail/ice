#pragma once

#include <map>
#include "pg_msg.h"
#include "media.h"

namespace ICE {
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

    public:
        Session();
        virtual ~Session();

        bool MakeOffer(std::string& offer);
        bool MakeAnswer(const std::string& remoteOffer, std::string& answer);

    private:
        using MediaContainer        = std::map<std::string, Media*>;

    private:
        SessionConfig           m_Config;
        MediaContainer          m_Medias;
        std::string             m_DefaultIP;
    };
}