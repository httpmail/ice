#pragma once

#include <stdint.h>
#include <string>

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
        Candidate(TypeRef eType, uint8_t compId, uint16_t localPref, bool bUDP,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP);

        virtual ~Candidate() = 0 {}

        uint32_t Foundation()   const { return m_Foundation; }
        uint32_t Priority()     const { return m_Priority; }
        uint16_t ComponentId()  const { return m_CompId; }

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

        static uint32_t ComputeFoundations(TypeRef type, const std::string& baseIP, const std::string& serverIP, bool bUDP);

    private:
        const TypeRef   m_TypeRef;
        const uint8_t   m_CompId;

        const std::string m_IP;
        const uint16_t    m_Port;

        const std::string m_RelatedIP;
        const uint16_t    m_RelatedPort;

        const uint32_t  m_Foundation;
        const uint32_t  m_Priority;
    };

    class HostCandidate : public Candidate {
    public:
        HostCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(TypeRef::host, compId, localPref, true, baseIP, basePort, baseIP, basePort, baseIP)
        {
        }

        virtual ~HostCandidate() {}
    };

    class ActiveCandidate : public Candidate {
    public:
        ActiveCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP) :
            Candidate(TypeRef::host, compId, localPref, false, baseIP, basePort, relatedIP, relatedPort, serverIP)
        {
        }

        virtual ~ActiveCandidate() {}
    };

    class PassiveCandidate : public Candidate {
    public:
        PassiveCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP) :
            Candidate(TypeRef::host, compId, localPref, false, baseIP, basePort, relatedIP, relatedPort,serverIP)
        {
        }

        virtual ~PassiveCandidate() {}
    };

    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP):
            Candidate(TypeRef::server_reflexive, compId, localPref, false, baseIP, basePort, relatedIP, relatedPort, serverIP)
        {
        }

        virtual ~SrflxCandidate() {}
    };

    class RelayedCandidate : public Candidate {
    public:
        RelayedCandidate(uint8_t compId, uint16_t localPref,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort, const std::string& serverIP) :
            Candidate(TypeRef::server_reflexive, compId, localPref, false, baseIP, basePort, relatedIP, relatedPort, serverIP)
        {
        }
        virtual ~RelayedCandidate() {}
    };

}