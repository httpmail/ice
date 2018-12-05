#include "candidate.h"
#include "stunmsg.h"
#include "channel.h"

ICE::Candidate::Candidate(type_ref eTypeRef, uint8_t comp_id, uint16_t localRef, uint64_t tiebreaker) :
    m_TypeRef(eTypeRef), m_ComponentId(comp_id), m_LocalRef(localRef),
    m_Priority(FormulaPriority(eTypeRef, m_LocalRef, comp_id)),
    m_Tiebreaker(tiebreaker)
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

bool ICE::Candidate::ConnectivityCheck(const CheckParam & checkparam)
{
    using namespace STUN;
    assert(m_pChannel);

    class Checker : public PG::Subscriber {
    public:
        enum class Status{
            waiting, /* waiting recv msg*/
            timeout,
            RecvBadReq,
            Succeed,
            Failed,
            Quit
        };

    public:
        Checker(const CheckParam& checkparam, bool bControlling) :
            m_param(checkparam), m_Status(Status::waiting)
        {
        }

        ~Checker()
        {
        }

        Status WaitForStatus(uint32_t timeoutMS)
        {
            std::unique_lock<decltype(m_Mutex)> locker(m_Mutex);
            auto ret = m_Cond.wait_for(locker, std::chrono::milliseconds(timeoutMS), [this] {
                return this->m_Status != Status::waiting;
            });

            return !ret ? Status::timeout : m_Status;
        }

        void OnPublished(PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam)
        {
            InternalMsg msg_id = static_cast<InternalMsg>(msgId);
            switch (msg_id)
            {

            case ICE::Candidate::InternalMsg::BindRequest:
            {
                BindingRequestMsg *pMsg = reinterpret_cast<BindingRequestMsg*>(wParam);
                assert(pMsg);
                HandleRequestMsg(*pMsg);
            }
                break;
            case ICE::Candidate::InternalMsg::BindResp:
            {
                BindRespMsg *pMsg = reinterpret_cast<BindRespMsg*>(wParam);
                assert(pMsg);
                HandleResponseMsg(*pMsg);
            }
                break;
            case ICE::Candidate::InternalMsg::BindErrResp:
                break;

            case ICE::Candidate::InternalMsg::Quit:
                m_Status = Status::Quit;
                m_Cond.notify_one();
                break;

            default:
                break;
            }
        }

    private:
        void HandleRequestMsg(const BindingRequestMsg& requestMsg)
        {
            const ATTR::MessageIntegrity* pMsgIntegrity = nullptr;
            const ATTR::UserName* pUserName = nullptr;

            requestMsg.GetAttribute(pMsgIntegrity);
            requestMsg.GetAttribute(pUserName);

            /*
             RFC5389 10.1.2.  Receiving a Request
            */
            if (!requestMsg.GetAttribute(pMsgIntegrity) && !requestMsg.GetAttribute(pUserName))
            {
                m_Status = Status::RecvBadReq;
                m_Cond.notify_one();
            }
            else if (pUserName->Name() != m_param.UserName())
            {
                //m_ErrorCode = 401;
                //m_Reason = "mismatched username";
                m_Status = Status::RecvBadReq;
                m_Cond.notify_one();
            }
            else if (!MessagePacket::VerifyMsgIntegrity(requestMsg, m_param.Password()))
            {
                //m_ErrorCode = 401;
                //m_Reason = "mismatched message integrity";
                m_Status = Status::RecvBadReq;
                m_Cond.notify_one();
            }
            else
            {
                // Detecting and Repairing Role Conflicts
                const ATTR::Role *pRole = nullptr;
                assert(requestMsg.GetAttribute(pRole));
            }
        }

        void HandleResponseMsg(const BindRespMsg& respMsg)
        {
            if (!MessagePacket::VerifyMsgIntegrity(respMsg, m_param.Password()))
            {
                /* RFC5389 10.1.3. Receiving a Response*/
                LOG_WARNING("Candidate","ConnectivityCheck : mismatched MsgIntegrity, just discard this response");
            }

            /*RFC5389 7.3.3.  Processing a Success Response*/
            const ATTR::XorMappedAddress* pXorMappAddr = nullptr;
            if (!respMsg.GetAttribute(pXorMappAddr))
            {

            }
        }

        void HandleErrorResponseMsg()
        {
        }

    private:
        Status m_Status;  /* never set Status to 'timeout' */
        std::mutex m_Mutex;
        std::condition_variable m_Cond;
        const CheckParam &m_param;
    };

    return true;
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

bool ICE::HostCandidate::CheckConnectivity(const std::string& remote, uint16_t port, const std::string& key, const std::string& username)
{
    return true;
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
    using namespace STUN;

    class MsgHelper : public PG::Subscriber {
    public:
        enum class Status{
            waiting,
            timeout,
            succeed,
            failed,
            quit
        };
    public:
        MsgHelper() :
            m_Status(Status::waiting)
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
                    const STUN::ATTR::XorMappedAddress *pXormapAddr = nullptr;
                    assert(pMsg->GetAttribute(pXormapAddr));

                    m_IP = pXormapAddr->IP();
                    m_Port = pXormapAddr->Port();
                    m_Condition.notify_one();
                }
                break;

            case ICE::Candidate::InternalMsg::BindErrResp:
                LOG_ERROR("SrflxCandidate", "1st Bind Request Received error bind response");
                m_Status = Status::failed;
                m_Condition.notify_one();
                break;

            case ICE::Candidate::InternalMsg::Quit:
                m_Status = Status::quit;
                m_Condition.notify_one();
                break;
            default:
                break;
            }
        }

        Status WaitBindResp(uint32_t timoutMs)
        {
            std::unique_lock<decltype(m_RecvRespMutex)> locker(m_RecvRespMutex);
            auto ret = m_Condition.wait_for(locker, std::chrono::milliseconds(timoutMs), [this] {
                return this->m_Status != Status::waiting;
            });

            return ret == false ? Status::timeout : m_Status;
        }

    public:
        std::mutex                     m_RecvRespMutex;
        std::condition_variable        m_Condition;
        Status                         m_Status;
        std::string                    m_IP;
        uint16_t                       m_Port;
        std::atomic_flag               m_bFlag;
    };


    TransId id;
    MessagePacket::GenerateRFC5389TransationId(id);
    RFC53891stBindRequestMsg bindMsg(id);

    auto channel = dynamic_cast<UDPChannel*>(m_pChannel);
    assert(channel);

    if (!channel->BindRemote(remote, port))
    {
        LOG_ERROR("SrflxCandidate", "Bind Remote[%s:%d] error", remote.c_str(), port);
        return false;
    }

    MsgHelper msgHelper;
    Subscribe(InternalMsg::BindErrResp, &msgHelper);
    Subscribe(InternalMsg::BindRequest, &msgHelper);

    bool bResult = false;

    while (1)
    {
        if(!m_pChannel->Write(bindMsg.GetData(), bindMsg.GetLength()))
        {
            LOG_ERROR("SrflxCandidate", "Send 1st Bind Request Error");
        }
        auto status = msgHelper.WaitBindResp(0);
        switch (status)
        {
        case MsgHelper::Status::timeout:
            break;
        case MsgHelper::Status::succeed:
            break;
        case MsgHelper::Status::failed:
            break;
        case MsgHelper::Status::quit:
            break;
        default:
            break;
        }

        if (MsgHelper::Status::timeout == status)
            continue;
        else if (MsgHelper::Status::succeed == status)
            return true;
        else if (MsgHelper::Status::failed == status)
        {
            LOG_WARNING("SrflxCandidate", "Send 1st Bind Request received error resp");
            return false;
        }
        else
        {
            LOG_WARNING("SrflxCandidate", "process was terminated!");
            return false;
        }
    }

    LOG_WARNING("SrflxCandidate", "Send 1st Bind Request timout");
    return bResult;
}
