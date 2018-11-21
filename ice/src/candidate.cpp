
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
        m_pChannel(nullptr), m_State(State::init), m_Quit(false), m_Config(config)
    {
        RegisterEvent(static_cast<uint16_t>(Msg::gathering));
        RegisterEvent(static_cast<uint16_t>(Msg::checking));

        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::BindRequest));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::BindResp));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::BindErrResp));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::SSReq));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::SSErrResp));
        m_InternalEventPub.RegisterMsg(static_cast<MSG_ID>(InternalEvent::SSResp));

        m_HandleThrd = std::thread(Candidate::HandlePacketThread, this);
    }

    Candidate::~Candidate()
    {
        m_RecvBuffer.ReleaseLocker();

        m_Quit = true;
        delete m_pChannel;
        m_pChannel = nullptr;

        if (m_GatheringThrd.joinable())
            m_GatheringThrd.join();

        if (m_RecvThrd.joinable())
            m_RecvThrd.join();

        if (m_ConnThrd.joinable())
            m_ConnThrd.join();

        if (m_HandleThrd.joinable())
            m_HandleThrd.join();

        delete m_pChannel;
    }

    bool Candidate::StartGathering()
    {
        assert(m_pChannel);

        if (!IsState(State::init))
        {
            LOG_WARNING("Candidate", "gathering only worked on init state, Current State: %d",
                static_cast<uint8_t>(m_State.load()));
            return false;
        }

        SetState(State::gathering);
        m_RecvThrd = std::thread(Candidate::RecvThread, this);
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

    bool Candidate::Subscribe(PG::Subscriber *subscriber, InternalEvent event)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        return m_InternalEventPub.Subscribe(subscriber, static_cast<uint16_t>(event));
    }

    bool Candidate::Unsubscribe(PG::Subscriber * subscriber)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        return m_InternalEventPub.Unsubscribe(subscriber);
    }

    bool Candidate::Unsubscribe(PG::Subscriber * subscriber, InternalEvent event)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
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
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindRequest), (WPARAM)&reqMsg, nullptr);
    }

    void Candidate::OnStunMsg(const BindingRespMsg & respMsg)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindResp), (WPARAM)&respMsg, nullptr);
    }

    void Candidate::OnStunMsg(const BindingErrRespMsg & errRespMsg)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::BindErrResp), (WPARAM)&errRespMsg, nullptr);
    }

    void Candidate::OnStunMsg(const SharedSecretRespMsg & ssRespMsg)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::SSResp), (WPARAM)&ssRespMsg, nullptr);
    }

    void Candidate::OnStunMsg(const SharedSecretReqMsg & ssReqMsg)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::SSReq), (WPARAM)&ssReqMsg, nullptr);
    }

    void Candidate::OnStunMsg(const SharedSecretErrRespMsg & errSSRespMsg)
    {
        std::lock_guard<decltype(m_InternalEventPubMutex)> locker(m_InternalEventPubMutex);
        m_InternalEventPub.Publish(static_cast<uint16_t>(InternalEvent::SSErrResp), (WPARAM)&errSSRespMsg, nullptr);
    }

    void Candidate::RecvThread(Candidate* pOwn)
    {
        while (!pOwn->m_Quit)
        {
            PACKET::stun_packet* packet = pOwn->m_RecvBuffer.LockWriter();
            if (packet && !pOwn->m_Quit)
            {
                auto read_bytes = pOwn->m_pChannel->Read(packet, sizeof(PACKET::stun_packet));
                LOG_INFO("Candidate", "RecvThread [%d]", read_bytes);
                pOwn->m_RecvBuffer.UnlockWriter(read_bytes <= 0);
            }
        }
    }

    void Candidate::HandlePacketThread(Candidate * pOwn)
    {
        while (!pOwn->m_Quit)
        {
            PACKET::stun_packet* packet = pOwn->m_RecvBuffer.LockReader();
            if (packet && !pOwn->m_Quit)
            {
                LOG_INFO("Candidate", "HandlePacketMsg :%d", packet->MsgId());

                switch (packet->MsgId())
                {
                case MsgType::BindingRequest:
                    pOwn->OnStunMsg(BindingRequestMsg(*packet));
                    break;

                case MsgType::BindingErrResp:
                    pOwn->OnStunMsg(BindingErrRespMsg(*packet));
                    break;

                case MsgType::BindingResp:
                    pOwn->OnStunMsg(BindingRespMsg(*packet));
                    break;

                case MsgType::SSErrResp:
                    pOwn->OnStunMsg(BindingErrRespMsg(*packet));
                    break;

                case MsgType::SSRequest:
                    pOwn->OnStunMsg(SharedSecretReqMsg(*packet));
                    break;

                case MsgType::SSResponse:
                    pOwn->OnStunMsg(SharedSecretRespMsg(*packet));
                    break;
                default:
                    break;
                }
                pOwn->m_RecvBuffer.UnlockReader(false);
            }
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

        auto ret = pOwn->DoGathering();
        pOwn->NotifyListener(static_cast<PG::MsgEntity::MSG_ID>(Msg::gathering), PG::MsgEntity::WPARAM(ret), 0);
    }

    /////////////////////////// HostCandidate class ////////////////////////////////////
    HostCandidate::~HostCandidate()
    {
    }

    bool HostCandidate::Create(const std::string & localIP, uint16_t port)
    {
        auto channel = CreateChannel<ICE::UDPChannel, boost::asio::ip::udp::socket, boost::asio::ip::udp::endpoint>(localIP, port);

        if (channel)
        {
            m_pChannel = channel;
            return true;
        }

        return false;
    }

    bool HostCandidate::DoGathering()
    {
        return m_pChannel != nullptr;
    }

    /////////////////////////// ActiveCandidate class ////////////////////////////////////
    ActiveCandidate::ActiveCandidate(const ICE::CAgentConfig& config):
        HostCandidate(config)
    {
    }

    ActiveCandidate::~ActiveCandidate()
    {
    }

    bool ActiveCandidate::Create(const std::string & localIP, uint16_t port)
    {
        auto channel = CreateChannel<ICE::TCPActiveChannel, boost::asio::ip::tcp::socket, boost::asio::ip::tcp::endpoint>(localIP, port);
        if (channel)
        {
            m_pChannel = channel;
            return true;
        }
        return false;
    }

    /////////////////////////// PassiveCandidate class ////////////////////////////////////
    PassiveCandidate::PassiveCandidate(const ICE::CAgentConfig& config) :
        HostCandidate(config)
    {
    }

    PassiveCandidate::~PassiveCandidate()
    {
    }

    bool PassiveCandidate::Create(const std::string & localIP, uint16_t port)
    {
        auto channel = CreateChannel<ICE::TCPPassiveChannel, boost::asio::ip::tcp::socket, boost::asio::ip::tcp::endpoint>(localIP, port);
        if (channel)
        {
            m_pChannel = channel;
            return true;
        }
        return false;
    }

    /////////////////////////// SrflxCandidate class ////////////////////////////////////
    SrflxCandidate::~SrflxCandidate()
    {
    }

    bool SrflxCandidate::Create(const std::string & localIP, uint16_t port)
    {
        auto channel = CreateChannel<ICE::UDPChannel, boost::asio::ip::udp::socket, boost::asio::ip::udp::endpoint>(localIP, port);
        if (channel && channel->BindRemote(m_StunServer, m_StunPort))
        {
            m_pChannel = channel;
            return true;
        }
        return false;
    }

    bool SrflxCandidate::DoGathering()
    {
        assert(m_pChannel);

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
                int a = 0;
                a++;
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
                LOG_INFO("xxxxx", "Resp");
                return std::cv_status::no_timeout == m_Cond.wait_for(locker, std::chrono::milliseconds(msec));
            }

            TransId m_TransId;
            RFC53891stBindRequestMsg m_ReqMsg;
            std::condition_variable  m_Cond;
            SrflxCandidate          *m_pOwner;
        };

        BindRespSubscriber subscriber(id, this);

        uint16_t retransmission_cnt = 0;
        uint32_t rto = m_Config.RTO();
        while (++retransmission_cnt < m_Config.Rc())
        {
            // send the first bind request
            if (-1 == m_pChannel->Write(subscriber.m_ReqMsg.GetData(), subscriber.m_ReqMsg.GetLength()))
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
            LOG_INFO("acb", "1 %d", rto);
            if (subscriber.WaitForResp(rto))
            {
                return true;
            }
            else
            {
                LOG_INFO("SrflxCandidate", "1st bind request timeout, retransmission [next timeout :%dms], [RC :%d]", 
                    rto,
                    retransmission_cnt - 1);
            }
            LOG_INFO("acb", "2");
        }
        LOG_WARNING("SrflxCandidate", "1st bind request failed, because of timeout");
        return false;
    }
}