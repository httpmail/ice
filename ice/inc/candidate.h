
#pragma once

#if 0
#include <string>
#include <boost/asio.hpp>

namespace ICE {
    class CChannel;

    class Candidate {
    public:
        enum class ChannelType {
            UDP,
            TCP_PASSIVE,
            TCP_ACT,
        };

    public:
        Candidate(uint8_t comp_id);
        virtual ~Candidate() {}
        inline bool STUN::Candidate::StartChecking()
        {
            return false;
        }
        virtual std::string TypeName()       const = 0;
        virtual uint8_t    TypePreference()  const = 0;
        virtual uint16_t   LocalPreference() const = 0;

        bool Initilize(ChannelType eType, const std::string& ip = "", int port = 0);

    protected:
        static CChannel*    CreateChannel(ChannelType eType);
        static uint32_t     CalcBKDRHash(const std::string& str);

    protected:
        uint32_t        m_priority;
        std::string     m_foundation;
        std::string     m_baseAddress;
        CChannel        *m_pChannel;
        const uint8_t   m_componet_id;
    };

    class HostCandidate : public Candidate {
    public:
        HostCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        inline STUN::HostCandidate::HostCandidate()
        {
        }
        virtual ~HostCandidate() {}

        virtual std::string TypeName() const override final        { return "host"; }
        virtual uint8_t     TypePreference() const override final  { return 126; /* RFC5245 4.1.2.2 */}
        virtual uint16_t    LocalPreference() const override final { return 65535; }
    };

    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~SrflxCandidate() {}

        virtual std::string TypeName() const override final        { return "srflx"; }
        virtual uint8_t     TypePreference() const override final  { return 100; /* RFC5245 4.1.2.2 */}
        virtual uint16_t    LocalPreference() const override final { return 65535;}

    protected:
        CChannel *m_pSflxChannel;
    };

    class RelayedCandidate : public Candidate {
        RelayedCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~RelayedCandidate() {}

        virtual std::string TypeName() const override final         { return "relayed"; }
        virtual uint8_t     TypePreference() const override final   { return 0; /* RFC5245 4.1.2.2 */}
        virtual uint16_t    LocalPreference() const override final  { return 65535; }

    protected:
        CChannel *m_pSflxChannel;
    };

    class PeerSrflxCandidate : public Candidate {
    public:
        PeerSrflxCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~PeerSrflxCandidate() {}

        virtual std::string TypeName() const override final       { return "srflx"; }
        virtual uint8_t     TypePreference() const override final { return 110; /* RFC5245 4.1.2.2 */ }
        virtual uint16_t    LocalPreference() const override final{ return 65535; }

    protected:
        CChannel *m_pSflxChannel;
    };
}
#endif

#include <thread>
#include <atomic>
#include <type_traits>

#include "stundef.h"

#include "pg_util.h"
#include "pg_log.h"
#include "pg_buffer.h"

namespace ICE {
    class Channel;
    class CAgent;
    class Session;
    class CAgentConfig;
}

namespace STUN {
    class Candidate {
    public:
        enum class OP {
            gathering,
            checking,
        };

    public:
        Candidate(const ICE::CAgentConfig& config);
        virtual ~Candidate() = 0 {}

    public:
        bool StartGathering();
        bool StartChecking();

    public:
        virtual uint8_t TypePreference()    = 0;
        virtual uint8_t LocalPrefrerence()  = 0;

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
                    {
                        // active recv thread
                        m_RecvThrd = std::thread(Candidate::RecvThread,this);
                        return channel.release();
                    }
                    LOG_WARNING("Candidate", "Create Channel [%s:%d] failed, try to bind with random port", ep.address().to_string(), ep.port());
                }

                for (int16_t i = 0; i < sMaxBindTries; ++i)
                {
                    auto portRange = m_Config.GetPortRange();
                    ep.port(PG::GenerateRandom(portRange.Lower(), portRange.Upper()));
                    if (channel->BindSocket<socket_type, endpoint_type>(channel->Socket(), ep))
                    {
                        LOG_INFO("Candidate", "Create Channel [%s:%d] succeed", ep.address().to_string(), ep.port());

                        // active recv thread
                        m_RecvThrd = std::thread(Candidate::RecvThread, this);
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

        virtual void OnStunMsg() = 0;
        virtual bool DoGathering(const std::string& ip, int16_t port) = 0;
        virtual bool DoChecking()  = 0;

    protected:
        static const int16_t sMaxPacketSize = 128;

    protected:
        ICE::Channel            *m_pChannel;
        int16_t                  m_retransmission_cnt;
        PG::PacketBuffer<PACKET::stun_packet, sMaxPacketSize> m_RecvBuffer;

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
        static void RecvThread(Candidate* pOwn);
        static void CheckingThread(Candidate* pOwn);
        static void GatheringThread(Candidate* pOwn);

    private:
        std::thread m_RecvThrd;
        std::thread m_ConnThrd;
        std::thread m_GatheringThrd;
        std::atomic<State> m_State;
    };

    class HostCandidate : public Candidate{
    public:
        HostCandidate(const ICE::CAgentConfig& config);
        virtual ~HostCandidate();

    protected:
        virtual bool DoGathering(const std::string& ip, int16_t port) override;
//        virtual bool DoChecking() override;
    };

    class ActiveCandidate : public HostCandidate {
    public:
        ActiveCandidate(const ICE::CAgentConfig& config);
        virtual ~ActiveCandidate();

    protected:
        virtual bool DoGathering(const std::string& ip, int16_t port) override;
    };

    class PassiveCandidate : public HostCandidate {
    public:
        PassiveCandidate(const ICE::CAgentConfig& config);
        virtual ~PassiveCandidate();

    protected:
        virtual bool DoGathering(const std::string& ip, int16_t port) override;
    };

    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(const ICE::CAgentConfig& config, const std::string& stun_server_ip, int16_t stun_port);
        virtual ~SrflxCandidate();

    protected:
        virtual bool DoGathering(const std::string& ip, int16_t port) override;

    protected:
        const std::string& m_StunServer;
        const int16_t      m_StunPort;
    };
}