#pragma once

#include <stdint.h>
#include <string>
#include <assert.h>
#include "streamdef.h"

namespace STUN {
    class Candidate {
    public:
        enum class TypeRef {
            /*RFC8445 5.1.2.2.  Guidelines for Choosing Type and Local Preferences*/
            server_reflexive = 100,
            relayed = 0,
            host = 126,
            peer_reflexive = 110,
        };

    public:
        Candidate(TypeRef eType, uint8_t compId, uint16_t localPref, ICE::Protocol protocol,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP);
        
        Candidate(TypeRef eType, ICE::Protocol protocol, uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort):
            m_TypeRef(eType), m_CompId(compId), m_Priority(pri),
            m_IP(baseIP),m_Port(basePort),
            m_RelatedIP(relatedIP), m_RelatedPort(relatedPort),
            m_Foundation(foundation),
            m_Protocol(protocol)
        {
        }

        virtual ~Candidate() = 0 {}

        const std::string& Foundation()   const { return m_Foundation; }
        uint32_t           Priority()     const { return m_Priority; }
        uint16_t           ComponentId()  const { return m_CompId; }
        ICE::Protocol      Protocol()     const { return m_Protocol; }

        const std::string& TransationIP() const { return m_IP;  }
        uint16_t TransationPort()         const { return m_Port;}

        const std::string& RelatedIP() const { return m_RelatedIP; }
        uint16_t RelatedPort()         const { return m_RelatedPort; }

        std::string TypeName() const;

        bool IsHost() const { return m_TypeRef == TypeRef::host; }

    protected:
        static uint32_t ComputePriority(TypeRef type, uint32_t localPref, uint8_t comp_id)
        {
            return ((static_cast<uint8_t>(type) & 0xFF) << 24) + ((localPref & 0xFFFF) << 8) + (((256 - comp_id) & 0xFF) << 0);
        }

        static std::string ComputeFoundations(TypeRef type, const std::string& baseIP, const std::string& serverIP, ICE::Protocol protocol);

    private:
        const std::string m_IP;
        const std::string m_RelatedIP;
        const std::string m_Foundation;

        const uint32_t    m_Priority;
        const uint16_t    m_Port;

        const uint16_t    m_RelatedPort;

        const TypeRef  m_TypeRef;
        const uint8_t  m_CompId;
        const ICE::Protocol  m_Protocol;
    };

    class HostCandidate : public Candidate {
    public:
        HostCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(TypeRef::host, compId, localPref, ICE::Protocol::udp, baseIP, basePort, baseIP, basePort, baseIP)
        {
        }
        
        HostCandidate(uint8_t compId, uint32_t pri, const std::string& foundation, const std::string& ip, uint16_t port):
            Candidate(TypeRef::host, ICE::Protocol::udp, compId, pri, foundation, ip, port, ip, port)
        {
        }

        virtual ~HostCandidate() {}
    };

    class ActiveCandidate : public Candidate {
    public:
        ActiveCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP) :
            Candidate(TypeRef::host, compId, localPref, ICE::Protocol::tcp_act, baseIP, basePort, relatedIP, relatedPort, serverIP)
        {
        }
        ActiveCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,const std::string& ip, uint16_t port) :
            Candidate(TypeRef::host, ICE::Protocol::tcp_act, compId, pri, foundation, ip, port, ip, port)
        {
        }

        virtual ~ActiveCandidate() {}
    };

    class PassiveCandidate : public Candidate {
    public:
        PassiveCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP) :
            Candidate(TypeRef::host, compId, localPref, ICE::Protocol::tcp_pass, baseIP, basePort, relatedIP, relatedPort,serverIP)
        {
        }
        
        PassiveCandidate(uint8_t compId, uint32_t pri, const std::string& foundation, const std::string& ip, uint16_t port) :
            Candidate(TypeRef::host, ICE::Protocol::tcp_pass, compId, pri, foundation, ip, port, ip, port)
        {
        }

        virtual ~PassiveCandidate() {}
    };

    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP):
            Candidate(TypeRef::server_reflexive,compId, localPref, ICE::Protocol::udp, relatedIP, relatedPort, baseIP, basePort, serverIP)
        {
        }
        
        SrflxCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort) :
            Candidate(TypeRef::server_reflexive, ICE::Protocol::udp, compId, pri, foundation, relatedIP, relatedPort, baseIP, basePort)
        {
        }

        virtual ~SrflxCandidate() {}
    };

    class RelayedCandidate : public Candidate {
    public:
        RelayedCandidate(uint8_t compId, uint16_t localPref,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP) :
            Candidate(TypeRef::relayed, compId, localPref, ICE::Protocol::udp, relatedIP, relatedPort, relatedIP, relatedPort, serverIP)
        {
        }

        RelayedCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& relatedIP, uint16_t relatedPort) :
            Candidate(TypeRef::relayed, ICE::Protocol::udp, compId, pri, foundation, relatedIP, relatedPort, relatedIP, relatedPort)
        {
        }
        virtual ~RelayedCandidate() {}
    };

}