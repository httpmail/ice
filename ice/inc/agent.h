#pragma once

#include <string>
#include <map>
#include <set>

namespace ICE {
    class CSession;

    class CAgent {
    public:
        using SessionContainer = std::map<int, CSession*>;

    public:
        class CAgentConfig {
        public:
            using ServerContainer = std::set<std::string>;

        public:
            CAgentConfig();
            virtual ~CAgentConfig();

            bool AddStunServer(const std::string& stun_server)
            {
                return m_stun_server.insert(stun_server).second;
            }

            const ServerContainer& GetStunServer() const
            {
                return m_stun_server;
            }

            bool AddTurnServer(const std::string& turn_server)
            {
                return m_turn_server.insert(turn_server).second;
            }

            const ServerContainer& GetTurnServer() const
            {
                return m_turn_server;
            }

        private:
            ServerContainer m_stun_server;
            ServerContainer m_turn_server;
        };

    public:
        CAgent();
        virtual ~CAgent();

    private:
        bool DNSResolver(const std::string& domain);
        bool CreateSession();
        bool NATDetect(const std::string& server_ip);
        bool MakeOffer();
        bool MakeAnswer();

    protected:
        SessionContainer                 m_sessions;
        CAgentConfig::ServerContainer m_stun_server;
        CAgentConfig::ServerContainer m_turn_server;
    };
}