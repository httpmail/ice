#include "stream.h"
#include "candidate.h"
#include "stunmsg.h"
#include "agent.h"
#include "channel.h"
#include "pg_log.h"

namespace ICE {
    Stream::Stream(uint8_t compId, Pipline pipline, uint16_t localPref, const std::string & hostIp, uint16_t hostPort) :
        m_CompId(compId), m_Pipline(pipline), m_LocalPref(localPref), m_HostIP(hostIp), m_HostPort(hostPort), m_State(State::Init), m_Quit(false),
        m_GatherEventSub(this)
    {
        assert(hostPort);
        RegisterEvent(static_cast<PG::MsgEntity::MSG_ID>(Message::Gathering));
        RegisterEvent(static_cast<PG::MsgEntity::MSG_ID>(Message::Checking));
    }

    Stream::~Stream()
    {
        if (m_GatherThrd.joinable())
            m_GatherThrd.join();
    }

    bool Stream::Create(const CAgentConfig& config)
    {
        return false;
    }

    bool Stream::GatheringCandidate(const CAgentConfig& config)
    {
        // step 1> gather host candidate
        GatherHostCandidate(m_HostIP, m_HostPort, m_Pipline);

        auto &stun_server   = config.StunServer();
        auto &port_range    = config.GetPortRange();

        for (auto itor = stun_server.begin(); itor != stun_server.end(); ++itor)
        {
            GatherReflexiveCandidate(config.DefaultIP(), port_range.Lower(), port_range.Upper(), itor->first, itor->second);
            std::unique_lock<decltype(m_TaMutex)> locker(m_TaMutex);
            m_TaCond.wait_for(locker, std::chrono::milliseconds(config.Ta()));
        }

        auto &turn_server = config.TurnServer();
        for (auto itor = turn_server.begin(); itor != turn_server.end(); ++itor)
        {
            GatherRelayedCandidate(config.DefaultIP(), port_range.Lower(), port_range.Upper(), itor->first, itor->second);
            std::unique_lock<decltype(m_TaMutex)> locker(m_TaMutex);
            m_TaCond.wait_for(locker, std::chrono::milliseconds(config.Ta()));
        }

        if(!m_GatherThrd.joinable())
            m_GatherThrd = std::thread(Stream::WaitGatheringDoneThread, this);
        return true;
    }

    bool Stream::GatherHostCandidate(const std::string & ip, uint16_t port, Pipline pipline)
    {
        std::auto_ptr<Channel> channel(nullptr);
        switch (pipline)
        {
        case ICE::Stream::Pipline::udp:
            channel.reset(CreateChannel<UDPChannel>(ip, port));
            break;

        case ICE::Stream::Pipline::passive_tcp:
            channel.reset(CreateChannel<TCPPassiveChannel>(ip, port));
            break;

        case ICE::Stream::Pipline::active_tcp:
            channel.reset(CreateChannel<TCPActiveChannel>(ip, port));
            break;

        default:
            break;
        }

        if (!channel.get())
            return false;

        std::auto_ptr<STUN::HostCandidate> cand(new STUN::HostCandidate(m_CompId, m_LocalPref, ip, port));

        if (!cand.get())
            return false;

        {
            std::lock_guard<decltype(m_CandsMutex)> locker(m_CandsMutex);
            if (m_Cands.insert(std::make_pair(cand.get(), channel.get())).second)
            {
                cand.release();
                channel.release();
                LOG_INFO("Stream", "Host Candidate Created : [%s:%d]", ip.c_str(), port);
                return true;
            }
        }
        return false;
    }

    bool Stream::GatherReflexiveCandidate(const std::string & ip, uint16_t lowerPort, uint16_t upperPort, const std::string & stunIP, uint16_t stunPort)
    {
        /*
        RFC4389
        For example, assuming an RTO of 500 ms,
        requests would be sent at times 0 ms, 500 ms, 1500 ms, 3500 ms, 7500
        ms, 15500 ms, and 31500 ms.  If the client has not received a
        response after 39500 ms
         */

        static const ICE::Stream::StunGatherHelper::TimeOutInterval timeout = { 500, 1000,2000,4000,8000,16000, 8000};
        std::auto_ptr<UDPChannel> channel(CreateChannel<UDPChannel>(ip, lowerPort, upperPort, m_MaxTries));

        if (!channel.get() || !channel->BindRemote(stunIP, stunPort))
        {
            LOG_ERROR("Stream", "Create Channel Failed while tried to gather reflexive candidate from [%s]", stunIP.c_str());
            return false;
        }

        using namespace STUN;

        // build 1st bind request message
        TransId id;
        MessagePacket::GenerateRFC5389TransationId(id);
        RFC53891stBindRequestMsg *pMsg = new RFC53891stBindRequestMsg(id);

        std::auto_ptr<StunGatherHelper> helper(new StunGatherHelper(channel.get(), stunIP, stunPort, pMsg, timeout));
        {
            std::lock_guard<decltype(m_GatherMutex)> locker(m_GatherMutex);
            if (!helper.get() || !m_StunPendingGather.insert(helper.get()).second)
            {
                LOG_ERROR("Stream", "Start Gathering Failed [stun: %s, local: %s:%d]", stunIP.c_str(), channel->IP().c_str(), channel->Port());
                return false;
            }
            m_PendingGatherCnt++;
        }

        helper->Subscribe(&m_GatherEventSub, static_cast<uint16_t>(StunGatherHelper::PubEvent::GatheringEvent));
        helper->StartGathering();
        helper.release();
        channel.release();
        return true;
    }

    bool Stream::GatherRelayedCandidate(const std::string & ip, uint16_t lowerPort, uint16_t upperPort, const std::string & turnServer, uint16_t turnPort)
    {
        return true;
    }

    void Stream::WaitGatheringDoneThread(Stream * pThis)
    {
        assert(pThis);

        std::unique_lock<decltype(pThis->m_WaitingGatherMutex)> locker(pThis->m_WaitingGatherMutex);

        pThis->m_WaitingGatherCond.wait(locker, [pThis] {
            return pThis->m_PendingGatherCnt <= 0;
        });

        for (auto itor = pThis->m_StunPendingGather.begin(); itor != pThis->m_StunPendingGather.end(); ++itor)
        {
            auto helper = *itor;
            if (helper->IsOK())
            {
                std::auto_ptr<STUN::SrflxCandidate> cand(new STUN::SrflxCandidate(pThis->m_CompId,
                    pThis->m_LocalPref,
                    helper->m_Channel->IP(), helper->m_Channel->Port(),
                    helper->m_RelatedIP, helper->m_RelatedPort, helper->m_StunIP));

                if (cand.get())
                {
                    std::lock_guard<decltype(pThis->m_CandsMutex)> locker(pThis->m_CandsMutex);
                    if (pThis->m_Cands.insert(std::make_pair(cand.get(), helper->m_Channel)).second)
                    {
                        LOG_INFO("Stream", "SrflxCandidate Created, [%s:%d]", helper->m_Channel->IP(), helper->m_Channel->Port());
                        cand.release();
                    }
                }
            }
            (*itor)->Unsubscribe(&pThis->m_GatherEventSub);
        }
        pThis->m_StunPendingGather.clear();
    }

    ////////////////////////////// GatherHelper class //////////////////////////////
    Stream::StunGatherHelper::StunGatherHelper(ICE::Channel * channel, const std::string& stunServer, uint16_t stunPort, const STUN::FirstBindRequestMsg *pMsg, const TimeOutInterval & timeout) :
        m_Channel(channel), m_pBindReqMsg(pMsg), m_Timeout(timeout), m_Status(Status::waiting),m_StunIP(stunServer),m_StunPort(stunPort)
    {
        assert(timeout.size());
        assert(channel);
        assert(pMsg);
        this->RegisterMsg(static_cast<uint16_t>(PubEvent::GatheringEvent));
    }

    Stream::StunGatherHelper::~StunGatherHelper()
    {
        {
            std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
            m_Status = Status::quit;
        }

        m_Channel->Close();

        if (m_RecvThread.joinable())
            m_RecvThread.join();

        if (m_GatherThread.joinable())
            m_GatherThread.join();

        delete m_pBindReqMsg;
    }

    void Stream::StunGatherHelper::StartGathering()
    {
        assert(!m_GatherThread.joinable() && !m_RecvThread.joinable());
        m_GatherThread = std::thread(StunGatherHelper::GatheringThread, this);
        m_RecvThread   = std::thread(StunGatherHelper::ReceiveThread, this);
    }

    bool Stream::StunGatherHelper::OnStunMsg(const STUN::BindingRespMsg & msg)
    {
        LOG_INFO("Stream", "1st Bind Request Received Success Response");

        const STUN::ATTR::XorMappedAddress *pXormapAddr = nullptr;
        if (msg.GetAttribute(pXormapAddr))
        {
            {
                std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
                m_RelatedIP = pXormapAddr->IP();
                m_RelatedPort = pXormapAddr->Port();
                m_Status = Status::succeed;
            }
            m_Cond.notify_one();
            return true;
        }
        else
        {
            LOG_ERROR("Stream", "1st bind Request received RESPONSE without xormapaddress attributes ,just discards");
            return false;
        }
    }

    bool Stream::StunGatherHelper::OnStunMsg(const STUN::BindingErrRespMsg & msg)
    {
        LOG_WARNING("Stream", "1st Bind Request Received Error Response, Just set result to failed");
        {
            std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
            m_Status = Status::failed;
        }
        m_Cond.notify_one();
        return true;
    }

    void Stream::StunGatherHelper::ReceiveThread(StunGatherHelper * pThis)
    {
        assert(pThis && pThis->m_Channel);

        using namespace STUN;

        while(pThis->m_Status == Status::waiting)
        {
            STUN::PACKET::stun_packet packet;
            auto bytes = pThis->m_Channel->Read(&packet, sizeof(packet));

            if (bytes && MessagePacket::IsValidStunPacket(packet, bytes))
            {
                auto msg_id = packet.MsgId();
                MessagePacket msgPacket(packet, bytes);
                switch (msg_id)
                {
                case STUN::MsgType::BindingResp:
                    pThis->OnStunMsg(*reinterpret_cast<BindingRespMsg*>(&msgPacket));
                    break;

                case STUN::MsgType::BindingErrResp:
                    pThis->OnStunMsg(*reinterpret_cast<BindingErrRespMsg*>(&msgPacket));
                    break;

                default:
                    break;
                }
            }
        };
    }

    void Stream::StunGatherHelper::GatheringThread(StunGatherHelper * pThis)
    {
        assert(pThis && pThis->m_Channel);

        for (auto itor = pThis->m_Timeout.begin(); itor != pThis->m_Timeout.end(); ++itor)
        {
            if (!pThis->m_pBindReqMsg->SendData(*pThis->m_Channel))
            {
                LOG_ERROR("Stream", "Cannot send 1st bind request");
            }

            std::unique_lock<decltype(pThis->m_Mutex)> locker(pThis->m_Mutex);
            if (true == pThis->m_Cond.wait_for(locker, std::chrono::milliseconds(*itor), [pThis] {
                return pThis->m_Status != Status::waiting; }))
            {
                LOG_INFO("Stream", "Gather Candidate result :%d, [%s:%d]", pThis->m_Status, pThis->m_RelatedIP.c_str(), pThis->m_RelatedPort);
                break;
            }
            else
                pThis->m_Status = Status::failed;

            LOG_WARNING("Stream", "send 1st to stun :%s timout, try again()", pThis->m_Channel->PeerIP().c_str());
        }

        pThis->m_Channel->Shutdown(Channel::ShutdownType::both);  // close channel to wakeup recv thread
        pThis->Publish(static_cast<uint16_t>(PubEvent::GatheringEvent), (WPARAM)(pThis->m_Status == Status::succeed), nullptr);
    }

    Stream::GatherEventSubsciber::GatherEventSubsciber(Stream * pOwner) :
        m_pOwner(pOwner)
    {
        assert(m_pOwner);
    }

    /////////////////////////// GatherEventSubsciber ////////////////////
    void Stream::GatherEventSubsciber::OnPublished(const PG::Publisher * publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam)
    {
        assert(m_pOwner && publisher);
        assert(static_cast<StunGatherHelper::PubEvent>(msgId) == StunGatherHelper::PubEvent::GatheringEvent);

        {
            std::lock_guard<decltype(m_pOwner->m_GatherMutex)> locker(m_pOwner->m_GatherMutex);
            auto helper = dynamic_cast<const StunGatherHelper*>(publisher);
            assert(helper);
            assert(m_pOwner->m_StunPendingGather.find(const_cast<StunGatherHelper*>(helper)) != m_pOwner->m_StunPendingGather.end());
            m_pOwner->m_PendingGatherCnt--;
        }
        m_pOwner->m_TaCond.notify_one();
        if (m_pOwner->m_PendingGatherCnt <= 0)
        {
            LOG_INFO("Stream", "Gathering Stun Candidate Done");
            m_pOwner->m_WaitingGatherCond.notify_one();
        }
    }
}
