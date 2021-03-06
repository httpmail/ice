
#include "candidate.h"
#include <functional>
#include <boost/function.hpp>
#include <boost/lexical_cast.hpp>

#include "pg_log.h"

namespace STUN {
    Candidate::Candidate(TypeRef eType, uint8_t compId, uint16_t localPref, ICE::Protocol protocol,
        const std::string & baseIP, uint16_t basePort,
        const std::string & relatedIP, uint16_t relatedPort, const std::string& serverIP):
        m_TypeRef(eType), m_CompId(compId),m_Protocol(protocol),
        m_IP(baseIP),m_Port(basePort), m_RelatedIP(relatedIP),m_RelatedPort(relatedPort),
        m_Priority(ComputePriority(eType, localPref, compId)), m_Foundation(ComputeFoundations(eType, baseIP, serverIP, protocol))
    {
    }

    std::string Candidate::ComputeFoundations(TypeRef type, const std::string & baseIP, const std::string & serverIP, ICE::Protocol protocol)
    {
        char hashInfo[1024] = "";

        sprintf_s(hashInfo, sizeof(hashInfo), "%s%s%d%d", baseIP.c_str(), serverIP.c_str(), protocol, type);
        try
        {
            return boost::lexical_cast<std::string>(std::hash<std::string>{}(hashInfo));
        }
        catch (const std::exception&)
        {
            LOG_ERROR("Candidate","ComputeFoundation failed");
            return "0000";
        }
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
