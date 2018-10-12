#include "candidate.h"
#include "channel.h"
#include <boost/lexical_cast.hpp>
#include <memory>

namespace ICE {
    Candidate::Candidate(uint8_t comp_id) :
        m_componet_id(comp_id), m_pChannel(nullptr)
    {
    }

    CChannel* Candidate::CreateChannel(ChannelType eType)
    {
        if (ChannelType::TCP_ACT == eType)
            return new CTCPChannel;
        else if (ChannelType::TCP_PASSIVE == eType)
            return new CTCPChannel;
        else
            return new CUDPChannel;
    }

    uint32_t Candidate::CalcBKDRHash(const std::string & str)
    {
        uint32_t seed = 133;
        uint32_t hash = 0;

        for (auto s : str)
        {
            hash = hash * seed + s;
        }
        return hash & 0x7FFFFFFF;
    }

    bool Candidate::Initilize(ChannelType eType, const std::string& ip /*= ""*/, int port /*= 0*/)
    {
        std::auto_ptr<CChannel> channel(CreateChannel(eType));

        const std::string bindIP = "";// ip.length() ? ip : CDefaultAddress::Instance().Endpoint().address().to_string();

        // channel bind
        if (0 == port)
        {
        }
        else if(!channel->BindLocal(bindIP, port))
        {
            return false;
        }

        // calc foundation : RFC8445 5.1.1.3
        m_foundation = boost::lexical_cast<std::string>(CalcBKDRHash(bindIP 
            + TypeName() + boost::lexical_cast<std::string>(eType == ChannelType::UDP)));

        // calc priority : RFC8445 5.1.2.1
        m_priority = ((TypePreference() & 0x7E)     << 24) + 
                     ((LocalPreference() & 0xFFFF)  << 8) + 
                     (((256 - m_componet_id) & 0xFF)<< 0);
        m_pChannel = channel.release();
        return true;
    }
}
