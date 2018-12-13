
#include "candidate.h"
#include <functional>
#include <boost/function.hpp>

namespace STUN {
    Candidate::Candidate(TypeRef eType, uint8_t compId, uint16_t localPref, bool bUDP,
        const std::string & baseIP, uint16_t basePort,
        const std::string & relatedIP, uint16_t relatedPort, const std::string& serverIP):
        m_TypeRef(eType), m_CompId(compId),
        m_IP(baseIP),m_Port(basePort), m_RelatedIP(relatedIP),m_RelatedPort(relatedPort),
        m_Priority(ComputePriority(eType, localPref, compId)), m_Foundation(ComputeFoundations(eType, baseIP, serverIP, bUDP))
    {
    }

    uint32_t Candidate::ComputeFoundations(TypeRef type, const std::string & baseIP, const std::string & serverIP, bool bUDP)
    {
        char hashInfo[1024];

        sprintf_s(hashInfo, sizeof(hashInfo), "%s%s%d%d", baseIP.c_str(), serverIP.c_str(), bUDP, type);

        return std::hash<std::string>{}(hashInfo);
    }

    std::string Candidate::TypeName() const
    {
        /*
         RFC5245
         15.1.  "candidate" Attribute
         */
        switch (m_TypeRef)
        {
        case TypeRef::host:
            return "host";

        case TypeRef::relayed:
            return "relay";

        case TypeRef::server_reflexive:
            return "srflx";

        case TypeRef::peer_reflexive:
            return "prflx";

        default:
            return "host";
        }
    }
}
