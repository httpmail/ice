
#if 0
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

#endif

#include "candidate.h"
#include "agent.h"

#include "channel.h"
#include "stunmsg.h"
#include "stunprotocol.h"
#include "agent.h"

#include "pg_log.h"
#include "pg_util.h"

#include <assert.h>


namespace STUN {

    uint64_t Candidate::sRoleAttrContent;

    /////////////////////////// Candidate class ////////////////////////////////////
    Candidate::Candidate(const ICE::CAgentConfig& config) :
        m_pChannel(nullptr), m_State(State::init), m_Config(config), m_retransmission_cnt(0)
    {
    }

    bool Candidate::StartGathering()
    {
        if (!IsState(State::init))
        {
            LOG_WARNING("Candidate", "gathering only worked on init state, Current State: %d",
                static_cast<uint8_t>(m_State.load(std::memory_order_relaxed)));
            return false;
        }

        SetState(State::gathering);
        m_GatheringThrd = std::thread(Candidate::GatheringThread, this);
        return true;
    }

    bool Candidate::StartChecking()
    {
        if (!IsState(State::gathering_succeed))
        {
            LOG_WARNING("Candidate", "gathering only worked on gathering_succeed state, Current State: %d",
                static_cast<uint8_t>(m_State.load(std::memory_order_relaxed)));
            return false;
        }

        SetState(State::checking);
        m_ConnThrd = std::thread(Candidate::CheckingThread, this);

        return true;
    }

    bool Candidate::IsState(State eState)
    {
        return eState == m_State.load(std::memory_order_relaxed);
    }

    void  Candidate::SetState(State eState)
    {
        if (!IsState(eState))
            m_State.store(eState, std::memory_order_relaxed);
    }

    void Candidate::RecvThread(Candidate* pOwn)
    {
        while (1)
        {
            auto packet = pOwn->m_RecvBuffer.WaitFreePacket();
            assert(!packet.IsNull());
            pOwn->m_pChannel->Read(packet->Data(), packet->HeaderLength() + packet->PacketLength());
        }
    }

    void Candidate::CheckingThread(Candidate* pOwn)
    {
        assert(pOwn && pOwn->IsState(State::checking));

        //auto ret = pOwn->DoGathering();
        //pOwn->SetState(pOwn->DoGathering() ? State::checking_succeed : State::checking_failed);
    }

    void Candidate::GatheringThread(Candidate* pOwn)
    {
        assert(pOwn && pOwn->IsState(State::gathering));

        //auto ret = pOwn->DoGathering();
    }

    /////////////////////////// HostCandidate class ////////////////////////////////////
    HostCandidate::HostCandidate(const ICE::CAgentConfig& config) :
        Candidate(config)
    {
    }

    HostCandidate::~HostCandidate()
    {
    }

    bool HostCandidate::DoGathering(const std::string& ip, int16_t port)
    {
        auto channel = CreateChannel<ICE::UDPChannel, boost::asio::ip::udp::socket, boost::asio::ip::udp::endpoint>(ip, port);
        if (!channel)
        {
            LOG_ERROR("HostCandidate", "Create Local Channel [%s:%d] Failed!", ip.c_str(), port);
            return false;
        }
        return true;
    }

    /////////////////////////// ActiveCandidate class ////////////////////////////////////
    ActiveCandidate::ActiveCandidate(const ICE::CAgentConfig& config):
        HostCandidate(config)
    {
    }

    ActiveCandidate::~ActiveCandidate()
    {
    }

    bool ActiveCandidate::DoGathering(const std::string& ip, int16_t port)
    {
        auto channel = CreateChannel<ICE::TCPActiveChannel, boost::asio::ip::tcp::socket, boost::asio::ip::tcp::endpoint>(ip,port);
        if(!channel)
        {
            LOG_ERROR("HostCandidate", "Create Local Channel [%s:%d] Failed!", ip.c_str(), port);
            return false;
        }
        return true;
    }

    /////////////////////////// PassiveCandidate class ////////////////////////////////////
    PassiveCandidate::PassiveCandidate(const ICE::CAgentConfig& config) :
        HostCandidate(config)
    {
    }

    PassiveCandidate::~PassiveCandidate()
    {
    }

    bool PassiveCandidate::DoGathering(const std::string& ip, int16_t port)
    {
        auto channel = CreateChannel<ICE::TCPPassiveChannel, boost::asio::ip::tcp::socket, boost::asio::ip::tcp::endpoint>(ip, port);
        if (!channel)
        {
            LOG_ERROR("HostCandidate", "Create Local Channel [%s:%d] Failed!", ip.c_str(), port);
            return false;
        }
        return true;
    }

    /////////////////////////// SrflxCandidate class ////////////////////////////////////
    SrflxCandidate::SrflxCandidate(const ICE::CAgentConfig& config, const std::string& stun_server, int16_t stun_port)
        :Candidate(config), m_StunServer(stun_server), m_StunPort(stun_port)
    {
    }

    SrflxCandidate::~SrflxCandidate()
    {
    }

    bool SrflxCandidate::DoGathering(const std::string& ip, int16_t port)
    {
        BindingRequestMsg<PACKET::udp_stun_packet, PROTOCOL::RFC5389> msg(0);

        while (m_retransmission_cnt < m_Config.Rc())
        {
            m_retransmission_cnt++;

            auto channel = CreateChannel<ICE::UDPChannel, boost::asio::ip::udp::socket, boost::asio::ip::udp::endpoint>(ip, port);
            if (!channel || !channel->BindRemote(m_StunServer, m_StunPort))
            {
                LOG_ERROR("SrflxCandidate", "Create Local Channel[%s:%d] Failed!", ip.c_str(), port);
                return false;
            }

            // send the first bind request
            if (-1 == channel->Write(msg.GetData(), msg.GetLength()))
            {
                LOG_ERROR("SrflxCandidate", "Send BindRequestMsg Error");
                return false;
            }

            /* RFC8445 14.3.  RTO
               During the ICE gathering phase, ICE agents SHOULD calculate the RTO: value using the following formula:
               RTO = MAX (500ms, Ta * (Num-Of-Cands))

               !!!!!!! NOTICE !!!!!!!
               Here RTO simply considered as 500ms
            */
            auto ret = m_RecvBuffer.WaitForReadyPacket(std::chrono::milliseconds(m_Config.RTO() * (1 + m_retransmission_cnt*2)), [this] {
                auto packet = this->m_RecvBuffer.GetReadyPacket();
                if (!packet.IsNull())
                {
                    //TODO compare transation ID
                    return true;
                }
                else
                {
                    return false;
                }
            });
        }
        return false;
    }
}