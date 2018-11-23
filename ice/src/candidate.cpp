#include "candidate.h"
#include "stunmsg.h"
#include "channel.h"

ICE::Candidate::Candidate()
{
    using namespace PG;

    m_InternalMsgPub.RegisterMsg(static_cast<MsgEntity::MSG_ID>(InternalMsg::BindRequest));
    m_InternalMsgPub.RegisterMsg(static_cast<MsgEntity::MSG_ID>(InternalMsg::BindResp));
    m_InternalMsgPub.RegisterMsg(static_cast<MsgEntity::MSG_ID>(InternalMsg::BindErrResp));
    m_InternalMsgPub.RegisterMsg(static_cast<MsgEntity::MSG_ID>(InternalMsg::SSReq));
    m_InternalMsgPub.RegisterMsg(static_cast<MsgEntity::MSG_ID>(InternalMsg::SSResp));
    m_InternalMsgPub.RegisterMsg(static_cast<MsgEntity::MSG_ID>(InternalMsg::SSErrResp));
}

ICE::Candidate::~Candidate()
{
}

bool ICE::Candidate::Subscribe(InternalMsg msg, PG::Subscriber * subscriber)
{
    std::lock_guard<decltype(m_InternalMsgMutex)> locker(m_InternalMsgMutex);
    return m_InternalMsgPub.Subscribe(subscriber, static_cast<PG::MsgEntity::MSG_ID>(msg));
}

bool ICE::Candidate::Unsubscribe(InternalMsg msg, PG::Subscriber * subscriber)
{
    std::lock_guard<decltype(m_InternalMsgMutex)> locker(m_InternalMsgMutex);
    return m_InternalMsgPub.Unsubscribe(subscriber, static_cast<PG::MsgEntity::MSG_ID>(msg));
}

bool ICE::Candidate::Unsubscribe(PG::Subscriber * subscriber)
{
    std::lock_guard<decltype(m_InternalMsgMutex)> locker(m_InternalMsgMutex);
    return m_InternalMsgPub.Unsubscribe(subscriber);
}

void ICE::Candidate::RecvThread(Candidate * pThis)
{
    while (!pThis->m_bQuit)
    {
        assert(!pThis->m_pChannel);
        try
        {
            auto& packet = pThis->m_Packets.Lock4Write();
            auto bytes = pThis->m_pChannel->Read(packet.data(), sizeof(packet[0]));

            pThis->m_Packets.Unlock(packet, bytes <= 0);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Candidate", "Recv exception :%s", e.what());
        }
    }
}


////////////////////////////// Host Candidate //////////////////////////////
bool ICE::HostCandidate::Create(const std::string & local, uint16_t port)
{
    return (m_pChannel = CreateChannel<UDPChannel>(local, port)) == nullptr;
}

bool ICE::HostCandidate::Gather(const std::string &, uint16_t)
{
    return m_pChannel != nullptr;
}

bool ICE::HostCandidate::CheckConnectivity()
{
    return false;
}

////////////////////////////// ActiveCandidate //////////////////////////////
bool ICE::ActiveCandidate::Create(const std::string & local, uint16_t port)
{
    return (m_pChannel = CreateChannel<TCPActiveChannel>(local, port)) == nullptr;
}

////////////////////////////// PassiveCandidate //////////////////////////////
bool ICE::PassiveCandidate::Create(const std::string & local, uint16_t port)
{
    return (m_pChannel = CreateChannel<TCPPassiveChannel>(local, port)) == nullptr;
}

////////////////////////////// SrflxCandidate //////////////////////////////
bool ICE::SrflxCandidate::Create(const std::string & local, uint16_t port)
{
    return (m_pChannel = CreateChannel<UDPChannel>(local, port)) == nullptr;
}

bool ICE::SrflxCandidate::Gather(const std::string & remote, uint16_t port)
{
    assert(m_pChannel);

    STUN::TransId id;
    STUN::MessagePacket::GenerateRFC5389TransationId(id);

    class MsgHelper : public PG::Subscriber {
    public:
        enum class Status{
            timeout = 0,
            succeed,
            quit
        };
    public:
        MsgHelper(STUN::TransIdConstRef id) :
            m_Msg(id),m_bRecvResp(false), m_bQuit(false)
        {
        }

        void OnPublished(PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam)
        {
            InternalMsg msg_id = static_cast<InternalMsg>(msgId);
            LOG_INFO("SrflxCandidate", "1st Bind Request received Message [%d]", msg_id);

            switch (msg_id)
            {
            case ICE::Candidate::InternalMsg::BindResp:
                {
                    STUN::BindingRespMsg *pMsg = reinterpret_cast<STUN::BindingRespMsg*>(wParam);
                    auto attr = pMsg->GetAttribute(STUN::ATTR::Id::XorMappedAddress);
                    if (attr)
                    {
                        const STUN::ATTR::XorMappedAddress *address = reinterpret_cast<const decltype(address)>(attr);
                        m_IP = address->IP();
                        m_Port = address->Port();
                    }
                    else
                    {
                        attr = pMsg->GetAttribute(STUN::ATTR::Id::MappedAddress);
                        const STUN::ATTR::MappedAddress *address = reinterpret_cast<const decltype(address)>(attr);
                        m_IP = address->IP();
                        m_Port = address->Port();
                    }

                    assert(attr);

                    m_Condition.notify_one();
                }
                break;

            case ICE::Candidate::InternalMsg::BindErrResp:
                LOG_ERROR("SrflxCandidate", "1st Bind Request Received error bind response");
                break;

            case ICE::Candidate::InternalMsg::Quit:
                m_bQuit = true;
                m_Condition.notify_one();
                break;
            default:
                break;
            }
        }

        bool Send(Channel &channel)
        {
            return 0 >= channel.Write(m_Msg.GetData(), m_Msg.GetLength());
        }

        Status WaitBindResp(uint32_t timoutMs)
        {
            std::unique_lock<decltype(m_RecvRespMutex)> locker(m_RecvRespMutex);
            auto ret = m_Condition.wait_for(locker, std::chrono::milliseconds(timoutMs), [this]{
                return this->m_bRecvResp || m_bQuit;
            });

            if (m_bQuit)
                return Status::quit;
            return ret ? Status::succeed : Status::timeout;
        }

    public:
        STUN::RFC53891stBindRequestMsg m_Msg;
        bool                           m_bQuit;
        bool                           m_bRecvResp;
        std::mutex                     m_RecvRespMutex;
        std::condition_variable        m_Condition;
        std::string                    m_IP;
        uint16_t                       m_Port;
    };

    MsgHelper bindReq(id);

    auto channel = dynamic_cast<UDPChannel*>(m_pChannel);

    assert(channel);

    if (!channel->BindRemote(remote, port))
    {
        LOG_ERROR("SrflxCandidate", "Bind Remote[%s:%d] error", remote.c_str(), port);
        return false;
    }

    Subscribe(InternalMsg::BindErrResp, &bindReq);
    Subscribe(InternalMsg::BindRequest, &bindReq);

    while (1)
    {
        if (!bindReq.Send(*m_pChannel))
        {
            LOG_ERROR("SrflxCandidate", "Send 1st Bind Request Error");
            return false;
        }

        switch (bindReq.WaitBindResp(0))
        {
        case MsgHelper::Status::quit:
            return false;

        case MsgHelper::Status::succeed:
            m_SrflxIP = bindReq.m_IP;
            m_SrflxPort = bindReq.m_Port;
            return true;

        case MsgHelper::Status::timeout:
        default:
            break;
        }
    }
    return false;
}
