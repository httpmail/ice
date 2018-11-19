#include "stream.h"
#include "candidate.h"
#include "agent.h"

namespace ICE {

    Stream::~Stream()
    {
        if (m_GatherThrd.joinable())
            m_GatherThrd.join();
    }

    bool Stream::Create(const CAgentConfig& config)
    {
        if (m_State.load() != State::Init)
        {
            LOG_ERROR("Stream", "CreateStream only work on Init state, current[%d]", m_State);
            return false;
        }

        m_GatherThrd = std::thread(Stream::GatheringCandidate, this, config);
        return true;
    }

    void Stream::GatheringCandidate(Stream * pThis, const CAgentConfig& config)
    {
        assert(pThis);
        using namespace STUN;

        class GatheringHelper : public PG::CListener{
        public:
            GatheringHelper()  {}
            ~GatheringHelper() {}

        public:
            virtual void OnEventFired(PG::MsgEntity *pSender,
                PG::MsgEntity::MSG_ID msg_id,
                PG::MsgEntity::WPARAM wParam,
                PG::MsgEntity::LPARAM lParam) override
            {
                using namespace STUN;

                assert(pSender);
                assert(static_cast<Candidate::Msg>(msg_id) == Candidate::Msg::gathering);

                auto cand = dynamic_cast<Candidate*>(pSender);
                if (!cand || m_PendingCands.find(cand) == m_PendingCands.end())
                {
                    LOG_ERROR("Stream", "unexpected sender");
                    return;
                }

                m_PendingCands.erase(cand);
                cand->UnregisterEventListenner(static_cast<PG::MsgEntity::MSG_ID>(Candidate::Msg::gathering), this);

                if ((int)wParam)
                    m_ReadyCands.insert(cand);
                m_TimerCond.notify_one();
            }

            bool DoGathering(STUN::Candidate * cand, const std::string & IP, uint16_t port)
            {
                using namespace STUN;
                assert(cand);

                if (!m_PendingCands.insert(cand).second)
                    return false;

                if (!cand->RegisterEventListener(static_cast<PG::MsgEntity::MSG_ID>(Candidate::Msg::gathering), this))
                {
                    m_PendingCands.erase(cand);
                    return false;
                }

                if (!cand->StartGathering(IP, port))
                    return false;

                return true;
            }
            void WaitGathering(uint16_t millisecondsTimout)
            {
                std::unique_lock<std::mutex> locker(m_mutex);
                m_TimerCond.wait_for(locker, std::chrono::milliseconds(millisecondsTimout));
            }

            void WaitCompleted()
            {
                std::unique_lock<std::mutex> locker(m_mutex);
                m_TimerCond.wait(locker, [this] {
                    return this->m_PendingCands.empty();
                });
            }
        public:
            Stream::CandidateContainer m_PendingCands;
            Stream::CandidateContainer m_ReadyCands;
            std::mutex                 m_mutex;
            std::condition_variable    m_TimerCond;
        };

        GatheringHelper helper;
        // gathering host candidates
        {

            std::auto_ptr<Candidate> cand;
            switch (pThis->m_Pipline)
            {
            case Pipline::udp:
                cand = std::auto_ptr<HostCandidate>(new HostCandidate(config));
                break;

            case Pipline::active_tcp:
                cand = std::auto_ptr<ActiveCandidate>(new ActiveCandidate(config));
                break;

            case Pipline::passive_tcp:
                cand = std::auto_ptr<PassiveCandidate>(new PassiveCandidate(config));
                break;

            default:
                break;
            }

            if (!cand.get() || !helper.DoGathering(cand.release(), pThis->m_HostIP, pThis->m_HostPort))
            {
                LOG_ERROR("Stream", "Gathering Host Candidate Error");
            }
        }

        // gathering stun and turn candidate
        {
            auto stun_servers = config.StunServer();
            auto turn_servers = config.TurnServer();

            for (auto stun : stun_servers)
            {
                std::auto_ptr<SrflxCandidate> cand(new SrflxCandidate(config, stun.first, stun.second));

                if (!cand.get() || !helper.DoGathering(cand.release(), pThis->m_HostIP, 0))
                {
                    LOG_ERROR("Stream", "Gathering SrflxCandidate Error [%s:%d]", stun.first, stun.second);
                    continue;
                }
                helper.WaitGathering(50);
            }

            for (auto turn : turn_servers)
            {
                helper.WaitGathering(50);
            }
        }

        helper.WaitCompleted();
        if (helper.m_ReadyCands.size())
        {
            {
                std::lock_guard<std::mutex> locker(pThis->m_CandsMutex);
                pThis->m_Cands.insert(helper.m_ReadyCands.begin(), helper.m_ReadyCands.end());
            }
            pThis->m_State.store(State::CreateDone);
            pThis->NotifyListener(static_cast<PG::MsgEntity::MSG_ID>(Message::Gathering), (PG::MsgEntity::WPARAM)true, 0);
        }
        else
        {
            pThis->m_State.store(State::CreateFailed);
            pThis->NotifyListener(static_cast<PG::MsgEntity::MSG_ID>(Message::Gathering), (PG::MsgEntity::WPARAM)false, 0);
        }
    }
}
