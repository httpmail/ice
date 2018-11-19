
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
#include "pg_msg.h"
#include "pg_listener.h"

#include <assert.h>


namespace STUN {

    uint64_t Candidate::sRoleAttrContent;

    /////////////////////////// Candidate class ////////////////////////////////////
    Candidate::Candidate(const ICE::CAgentConfig& config) :
        m_pChannel(nullptr), m_State(State::init), m_Config(config), m_retransmission_cnt(0)
    {
        RegisterEvent(static_cast<uint16_t>(Msg::gathering));
        RegisterEvent(static_cast<uint16_t>(Msg::checking));

        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::BindRequest));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::BindResp));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::BindErrResp));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::SSReq));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::SSErrResp));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::SSResp));
    }

    bool Candidate::StartGathering(const std::string& ip, uint16_t port)
    {
        if (!IsState(State::init))
        {
            LOG_WARNING("Candidate", "gathering only worked on init state, Current State: %d",
                static_cast<uint8_t>(m_State.load(std::memory_order_relaxed)));
            return false;
        }

        SetState(State::gathering);
        m_GatheringThrd = std::thread(Candidate::GatheringThread, this, ip, port);
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

    bool Candidate::Subscribe(PG::Subscriber *subscriber, InternalEvent event)
    {
        return m_InternalEventPub.Subscribe(subscriber, static_cast<uint16_t>(event));
    }

    bool Candidate::Unsubscribe(PG::Subscriber * subscriber)
    {
        return m_InternalEventPub.Unsubscribe(subscriber);
    }

    bool Candidate::Unsubscribe(PG::Subscriber * subscriber, InternalEvent event)
    {
        return m_InternalEventPub.Unsubscribe(subscriber, static_cast<uint16_t>(event));
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

    void Candidate::OnStunMsg(const BindingRequestMsg & reqMsg)
    {
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&reqMsg, nullptr);
    }

    void Candidate::OnStunMsg(const BindingRespMsg & respMsg)
    {
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&respMsg, nullptr);
    }

    void Candidate::OnStunMsg(const BindingErrRespMsg & errRespMsg)
    {
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&errRespMsg, nullptr);
    }

    void Candidate::OnStunMsg(const SharedSecretRespMsg & ssRespMsg)
    {
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&ssRespMsg, nullptr);
    }

    void Candidate::OnStunMsg(const SharedSecretReqMsg & ssReqMsg)
    {
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&ssReqMsg, nullptr);
    }

    void Candidate::OnStunMsg(const SharedSecretErrRespMsg & errSSRespMsg)
    {
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&errSSRespMsg, nullptr);
    }

    void Candidate::RecvThread(Candidate* pOwn)
    {
        while (1)
        {
            auto packet = pOwn->m_RecvBuffer.WaitFreePacket();
            assert(!packet.IsNull());
            pOwn->m_pChannel->Read(packet.Data(), packet.Size());
        }
    }

    void Candidate::HandlePacketThread(Candidate * pOwn)
    {
        while (1)
        {
            auto packet = pOwn->m_RecvBuffer.WaitReadyPacket();

            assert(packet.IsNull());

            switch (packet->MsgId())
            {
            case MsgType::BindingRequest:
                pOwn->OnStunMsg(BindingRequestMsg(*packet.Data()));
                break;

            case MsgType::BindingErrResp:
                pOwn->OnStunMsg(BindingErrRespMsg(*packet.Data()));
                break;

            case MsgType::BindingResp:
                pOwn->OnStunMsg(BindingRespMsg(*packet.Data()));
                break;

            case MsgType::SSErrResp:
                pOwn->OnStunMsg(BindingErrRespMsg(*packet.Data()));
                break;

            case MsgType::SSRequest:
                pOwn->OnStunMsg(SharedSecretReqMsg(*packet.Data()));
                break;

            case MsgType::SSResponse:
                pOwn->OnStunMsg(SharedSecretRespMsg(*packet.Data()));
                break;
            default:
                break;
            }
        }
    }

    void Candidate::CheckingThread(Candidate* pOwn)
    {
        assert(pOwn && pOwn->IsState(State::checking));

        //auto ret = pOwn->DoGathering();
        //pOwn->SetState(pOwn->DoGathering() ? State::checking_succeed : State::checking_failed);
    }

    void Candidate::GatheringThread(Candidate* pOwn, const std::string& ip, uint16_t port)
    {
        assert(pOwn && pOwn->IsState(State::gathering));

        auto ret = pOwn->DoGathering(ip, port);
    }

    /////////////////////////// HostCandidate class ////////////////////////////////////
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
    SrflxCandidate::~SrflxCandidate()
    {
    }

    bool SrflxCandidate::DoGathering(const std::string& ip, int16_t port)
    {
        TransId id;
        MessagePacket::GenerateRFC5389TransationId(id);

        class BindRespSubscriber : public PG::Subscriber {
        public:
            BindRespSubscriber(TransIdConstRef id, SrflxCandidate *pOwner) :
                m_ReqMsg(id), m_pOwner(pOwner)
            {
                assert(m_pOwner);
                m_pOwner->Subscribe(this, InternalEvent::BindErrResp);
                m_pOwner->Subscribe(this, InternalEvent::BindResp);
            }
            ~BindRespSubscriber() 
            {
            }

            void OnPublished(MsgEntity::MSG_ID msgId, MsgEntity::WPARAM wParam, MsgEntity::LPARAM lParam) override
            {
                switch (static_cast<InternalEvent>(msgId))
                {
                case InternalEvent::BindResp:
                    {
                        BindingRespMsg *pMsg = reinterpret_cast<BindingRespMsg*>(wParam);
                        if (pMsg->IsTransIdEqual(m_ReqMsg))
                        {
                            ATTR::MappedAddress *mappedAddress = nullptr;
                            auto xOrMap = reinterpret_cast<const ATTR::XorMappedAddress*>(pMsg->GetAttributes(ATTR::Id::XorMappedAddress));
                            if (xOrMap)
                            {
                                m_pOwner->m_IP = xOrMap->IP();
                                m_pOwner->m_Port = xOrMap->Port();
                            }
                            else
                            {
                                auto mappedAddress = reinterpret_cast<const ATTR::MappedAddress*>(pMsg->GetAttributes(ATTR::Id::XorMappedAddress));
                                if (mappedAddress)
                                {
                                    m_pOwner->m_IP = mappedAddress->IP();
                                    m_pOwner->m_Port = mappedAddress->Port();
                                }
                            }
                            if (!(xOrMap || mappedAddress))
                            {
                                LOG_ERROR("SrflxCandidate", "Bind Response Message has no XorMappedAddress or MappedAddress");
                            }
                            else
                            {
                                m_pOwner->Unsubscribe(this);
                                m_Cond.notify_one();
                            }
                        }
                    }
                    break;

                case InternalEvent::BindErrResp:
                    {
                    }
                    break;
                default:
                    break;
                }
            }

            bool WaitForResp(uint32_t msec)
            {
                std::mutex mutex;
                std::unique_lock<std::mutex> locker(mutex);
                return std::cv_status::no_timeout == m_Cond.wait_for(locker, std::chrono::milliseconds(msec));
            }

            TransId m_TransId;
            RFC53891stBindRequestMsg m_ReqMsg;
            std::condition_variable  m_Cond;
            SrflxCandidate          *m_pOwner;
        };

        BindRespSubscriber subscriber(id, this);

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
            if (-1 == channel->Write(subscriber.m_ReqMsg.GetData(), subscriber.m_ReqMsg.GetLength()))
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
            if (subscriber.WaitForResp(m_Config.RTO() * (1 + m_retransmission_cnt * 2)))
            {
                return true;
            }
        }
        return false;
    }
}