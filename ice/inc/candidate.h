#pragma once

#include <stdint.h>
#include <string>
#include <assert.h>
#include "streamdef.h"

namespace ICE {
    class Candidate {
    public:
        /*RFC8445 5.1.2.2.  Guidelines for Choosing Type and Local Preferences*/
        enum class CandType{
            svr_ref     = 100,
            relayed     = 0,
            host        = 126,
            peer_ref    = 110,
        };

        Candidate(CandType type, uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            m_CandType(type),m_Priority(pri),m_Foundation(foundation),
            m_ConnIP(connIP),m_BaseIP(baseIP),m_ConnPort(connPort),m_BasePort(basePort)
        {
            assert(baseIP.length() && connIP.length() && connPort && basePort);
        }

        static uint32_t ComputePriority(CandType type, uint32_t localPref, uint8_t comp_id)
        {
            return ((static_cast<uint8_t>(type) & 0xFF) << 24) + ((localPref & 0xFFFF) << 8) + (((256 - comp_id) & 0xFF) << 0);
        }

        static uint32_t ComputeFoundations(CandType type, const std::string& baseIP, const std::string& serverIP, ICE::Protocol protocol);
    public:
        CandType       m_CandType;
        const uint32_t m_Priority;
        const uint32_t m_Foundation;
        const uint16_t m_ConnPort;
        const uint16_t m_BasePort;
        const std::string m_ConnIP;
        const std::string m_BaseIP;
    };

    class HostCand : public Candidate {
    public:
        HostCand(uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(CandType::host, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class ActiveCand : public Candidate {
    public:
        ActiveCand(uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(CandType::host, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class PassiveCand : public Candidate {
    public:
        PassiveCand(uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(CandType::host, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class SvrCand : public Candidate {
    public:
        SvrCand(uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(CandType::svr_ref, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class PeerCand : public Candidate {
    public:
        PeerCand(uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(CandType::peer_ref, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class RelayedCand : public Candidate {
    public:
        RelayedCand(uint32_t pri, uint32_t foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(CandType::relayed, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };
}