
#pragma once

#include <thread>
#include <atomic>
#include <type_traits>

#include "stundef.h"

#include "pg_util.h"
#include "pg_log.h"
#include "pg_buffer.h"
#include "pg_msg.h"

namespace ICE {
    class Channel;
    class CAgent;
    class Session;
    class CAgentConfig;
}

namespace STUN {
    class BindingRequestMsg;
    class BindingRespMsg;
    class BindingErrRespMsg;
    class SharedSecretRespMsg;
    class SharedSecretReqMsg;
    class SharedSecretErrRespMsg;
}

namespace STUN {
    class Candidate : public PG::MsgEntity{
    protected:
        static const int16_t sMaxPacketSize = 128;

    public:
        enum class Msg {
            gathering,
            checking,
        };

    public:
        Candidate(const ICE::CAgentConfig& config);
        virtual ~Candidate();

    public:
        bool StartGathering();
        bool StartChecking();

    public:
        virtual uint8_t TypePreference()    = 0;
        virtual uint8_t LocalPrefrerence()  = 0;
        virtual bool Create(const std::string& localIP, uint16_t port) = 0;

    protected:
        enum class InternalEvent : uint16_t {
            BindRequest,
            BindResp,
            BindErrResp,
            SSReq,
            SSResp,
            SSErrResp,
        };

    protected:
        template<class channel_type, class socket_type,class endpoint_type>
        channel_type* CreateChannel(const std::string& ip, int16_t port)
        {
            using namespace boost::asio::ip;
            static_assert(!std::is_pointer<channel_type>::value, "channel_type cannot be a pointer");
            static_assert(!std::is_pointer<socket_type>::value,  "socket_type cannot be a pointer");
            static_assert(!std::is_pointer<endpoint_type>::value, "endpoint_type cannot be a pointer");

            static_assert(std::is_base_of<ICE::UDPChannel, channel_type>::value && std::is_base_of<udp::socket, socket_type>::value && std::is_base_of<udp::endpoint, endpoint_type>::value ||
                std::is_base_of<ICE::TCPChannel, channel_type>::value && std::is_base_of<tcp::socket, socket_type>::value && std::is_base_of<tcp::endpoint,endpoint_type>::value,
                "wrong types");

            endpoint_type ep(boost::asio::ip::address::from_string(ip), port);
            try
            {
                std::auto_ptr<channel_type> channel(new channel_type);
                if (ep.port())
                {
                    if (channel->BindSocket<socket_type, endpoint_type>(channel->Socket(), ep))
                        return channel.release();
                    LOG_WARNING("Candidate", "Create Channel [%s:%d] failed, try to bind with random port", ep.address().to_string(), ep.port());
                }

                for (int16_t i = 0; i < sMaxBindTries; ++i)
                {
                    auto portRange = m_Config.GetPortRange();
                    ep.port(PG::GenerateRandom(portRange.Lower(), portRange.Upper()));
                    if (channel->BindSocket<socket_type, endpoint_type>(channel->Socket(), ep))
                    {
                        LOG_INFO("Candidate", "Create Channel [%s:%d] succeed", ep.address().to_string(), ep.port());
                        return channel.release();
                    }
                }

                LOG_INFO("Candidate", "Create Channel [%s:%d] failed");
                return nullptr;
            }
            catch (const std::exception &e)
            {
                LOG_ERROR("Candidate", "Create Channel[%s:%d] exception :%s", ep.address().to_string().c_str(), ep.port(), e.what());
                return nullptr;
            }

        }
        bool Subscribe(PG::Subscriber *subscriber, InternalEvent event);
        bool Unsubscribe(PG::Subscriber *subscriber);
        bool Unsubscribe(PG::Subscriber *subscriber, InternalEvent event);

        virtual bool DoGathering() = 0;
        virtual bool DoChecking() = 0;

    protected:
        ICE::Channel            *m_pChannel;
        PG::FIFOBuffer<PACKET::stun_packet, sMaxPacketSize> m_RecvBuffer;

        const ICE::CAgentConfig &m_Config;
        static uint64_t         sRoleAttrContent; /* */
        static const int16_t    sMaxBindTries = 5;

    private:
        enum class State : uint8_t {
            init = 0,
            gathering,
            gathering_succeed,
            gathering_failed,
            checking,
            checking_succeed,
            checking_failed,
            completed,
        };

    private:
        bool IsState(State eState);
        void SetState(State eState);

    private:
        void OnStunMsg(const BindingRequestMsg& reqMsg);
        void OnStunMsg(const BindingRespMsg& respMsg);
        void OnStunMsg(const BindingErrRespMsg& errRespMsg);
        void OnStunMsg(const SharedSecretRespMsg& ssRespMsg);
        void OnStunMsg(const SharedSecretReqMsg& ssReqMsg);
        void OnStunMsg(const SharedSecretErrRespMsg& errSSRespMsg);

    private:
        static void RecvThread(Candidate* pOwn);
        static void HandlePacketThread(Candidate *pOwn);
        static void CheckingThread(Candidate* pOwn);
        static void GatheringThread(Candidate* pOwn);

    private:
        std::thread m_RecvThrd;
        std::thread m_ConnThrd;
        std::thread m_GatheringThrd;
        std::thread m_HandleThrd;
        std::atomic<State> m_State;
        std::atomic_bool   m_Quit;
        std::recursive_mutex    m_InternalEventPubMutex;
        PG::Publisher           m_InternalEventPub;
    };

    class HostCandidate : public Candidate {
    public:
        using Candidate::Candidate;
        virtual ~HostCandidate();

    public:
        virtual uint8_t TypePreference() override
        {
            return 0;
        }

        virtual uint8_t LocalPrefrerence() override
        {
            return 1;
        }

        virtual bool Create(const std::string& localIP, uint16_t port) override;

    protected:
        virtual bool DoGathering() override;
        virtual bool DoChecking() override { return true; }
    };

    class ActiveCandidate : public HostCandidate {
    public:
        ActiveCandidate(const ICE::CAgentConfig& config);
        virtual ~ActiveCandidate();

    public:
        virtual bool Create(const std::string& localIP, uint16_t port) override;
    };

    class PassiveCandidate : public HostCandidate {
    public:
        PassiveCandidate(const ICE::CAgentConfig& config);
        virtual ~PassiveCandidate();

    public:
        virtual bool Create(const std::string& localIP, uint16_t port) override;

    };

    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(const ICE::CAgentConfig& config, const std::string& stun_server_ip, int16_t stun_port) :
            Candidate(config), m_StunServer(stun_server_ip), m_StunPort(stun_port)
        {
        }
        virtual ~SrflxCandidate();

    public:
        virtual bool Create(const std::string& localIP, uint16_t port) override;

    protected:
        virtual bool DoGathering() override;
        virtual uint8_t TypePreference() override
        {
            return 0;
        }

        virtual uint8_t LocalPrefrerence() override
        {
            return 1;
        }
        virtual bool DoChecking() override { return true; }

    protected:
        const std::string& m_StunServer;
        const int16_t      m_StunPort;

    private:
        std::string m_IP;
        uint16_t    m_Port;
    };
}