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
    /*
     RFC8445 7.2.2.Forming Credentials
     */
    using namespace STUN;
    UDPChannel *channel = dynamic_cast<UDPChannel*>(m_pChannel);
    assert(channel);

    if (!channel->BindRemote(remote, port))
        return false;

    // transation id
    TransId transId;
    MessagePacket::GenerateRFC5389TransationId(transId);

    // role attribute;
    ATTR::Role role(m_bControlling);
    role.TieBreaker(m_Tiebreaker);

    RFC5389SubBindReqMsg subMsg(m_Priority, transId, role);

    /*RFC8445 
     7.1.2.  USE-CANDIDATE
     The controlling agent MUST include the USE-CANDIDATE attribute
    */
    if (m_bControlling)
        subMsg.AddAttribute(STUN::ATTR::UseCandidate());

    //user name attribute;
    subMsg.AddUsername(username);

    uint8_t retransmission_cnt = 9;

    class MsgHelper : public PG::Subscriber {
    public:
        enum class Status {
            timeout,
            BindReqRecved,
            BindRespRecved,
            BindFailed,
            BindSucceed,
            quit,
        };

    public:
        MsgHelper(const SubBindRequestMsg& msg, TransIdConstRef id, const std::string& username, const std::string& key) :
            m_msg(msg),
            m_transId(id),
            m_ErrorCode(0),
            m_Reason(""),
            m_Username(username),m_Key(key)
        {
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
                    OnRecvBindRequest(*pMsg);
                }
                break;

            case ICE::Candidate::InternalMsg::BindResp:
                {
                    BindRespMsg *pMsg = reinterpret_cast<BindRespMsg*>(wParam);
                    assert(pMsg);
                    OnRecvBindResponse(*pMsg);
                }
                break;

            case ICE::Candidate::InternalMsg::BindErrResp:
                break;

            case ICE::Candidate::InternalMsg::Quit:
                m_Status = Status::quit;
                m_Condition.notify_one();
                break;
            default:
                break;
            }
        }

        Status WaitForResp(uint32_t timoutMs)
        {
            std::unique_lock<decltype(m_RecvRespMutex)> locker(m_RecvRespMutex);
            auto ret = m_Condition.wait_for(locker, std::chrono::milliseconds(timoutMs));

            return ret == std::_Cv_status::timeout ? Status::timeout : m_Status;
        }

    public:
        void OnRecvBindRequest(const BindingRequestMsg & bindReqMsg)
        {
            const ATTR::MessageIntegrity* pMsgIntegrity = reinterpret_cast<const ATTR::MessageIntegrity*>(bindReqMsg.GetAttribute(STUN::ATTR::Id::MessageIntegrity));
            const ATTR::UserName* pUserName = reinterpret_cast<const ATTR::UserName*>(bindReqMsg.GetAttribute(STUN::ATTR::Id::Username));
            if (!pMsgIntegrity && !pUserName)
            {
                m_ErrorCode = 400;
                m_Reason = "Bad Request";
                m_Status = Status::BindReqRecved;
                m_Condition.notify_one();
            }
            else if (pUserName->Name() != m_Username)
            {
                m_ErrorCode = 401;
                m_Reason = "mismatched username";
                m_Status = Status::BindReqRecved;
                m_Condition.notify_one();
            }
            else if (!MessagePacket::VerifyMsgIntegrity(bindReqMsg, m_Key))
            {
                m_ErrorCode = 401;
                m_Reason = "mismatched message integrity";
                m_Status = Status::BindReqRecved;
                m_Condition.notify_one();
            }

            const ATTR::XorMappedAddress* pXorMappedAddr = 
                reinterpret_cast<const ATTR::XorMappedAddress*>(bindReqMsg.GetAttribute(STUN::ATTR::Id::XorMappedAddress));

            if (!pXorMappedAddr)
                m_Status = Status::BindFailed;
            else
            {
                m_BindReqIP = pXorMappedAddr->IP();
                m_BindReqPort = pXorMappedAddr->Port();
            }
        }

        void OnRecvBindResponse(const BindRespMsg &bindResp)
        {
            /*RFC 10.1.3.  Receiving a Response*/
            if (MessagePacket::VerifyMsgIntegrity(bindResp, m_Key))
            {
                m_ErrorCode = 0;
                m_Reason = "";
                m_Status = Status::BindRespRecved;
                m_Condition.notify_one();
            }
        }

        void OnRecvBindErrorResponse(const BindingErrRespMsg &errBindResp)
        {
        }

    public:
        std::mutex                  m_RecvRespMutex;
        std::condition_variable     m_Condition;
        Status                      m_Status;
        uint16_t                    m_ErrorCode;
        std::string                 m_Reason;
        std::string                 m_BindReqIP;
        uint16_t                    m_BindReqPort;
        const SubBindRequestMsg    &m_msg;
        const std::string          &m_Key;
        const std::string          &m_Username;
        TransIdConstRef             m_transId;
    };

    MsgHelper msgHelper(subMsg,transId,username,key);
    Subscribe(InternalMsg::BindRequest, &msgHelper);
    Subscribe(InternalMsg::BindResp, &msgHelper);
    Subscribe(InternalMsg::BindErrResp, &msgHelper);
    Subscribe(InternalMsg::Quit, &msgHelper);

    while (retransmission_cnt--)
    {
        if (m_pChannel->Write(subMsg.GetData(), subMsg.GetLength()) <= 0)
        {
            LOG_ERROR("Candidate", "CheckConnectivity send bind Request failed");
        }

        auto status = msgHelper.WaitForResp(0);

        switch (status)
        {
        case MsgHelper::Status::timeout:
            break;

        case MsgHelper::Status::BindReqRecved:
            if (msgHelper.m_BindReqIP == remote && msgHelper.m_BindReqPort == port)

        case MsgHelper::Status::BindRespRecved:
            break;

        case MsgHelper::Status::BindFailed:
        case MsgHelper::Status::quit:
            return false;

        default:
            break;
        }
    }

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
            timeout = 0,
            succeed,
            failed,
            quit
        };
    public:
        MsgHelper()
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
                    assert(attr);

                    const STUN::ATTR::XorMappedAddress *address = reinterpret_cast<const decltype(address)>(attr);
                    m_IP = address->IP();
                    m_Port = address->Port();
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
            auto ret = m_Condition.wait_for(locker, std::chrono::milliseconds(timoutMs));

            return ret == std::cv_status::no_timeout ? m_Status : Status::timeout;
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
