#pragma once

#include <thread>
#include <stdint.h>

#include "pg_msg.h"
#include "pg_log.h"
#include "stundef.h"

namespace ICE {
    class Channel;

    class Candidate {
    public:
        Candidate();
        virtual ~Candidate();

    public:
        virtual bool Create(const std::string& local, uint16_t port) = 0;
        virtual bool Gather(const std::string& remote, uint16_t port) = 0;
        virtual bool CheckConnectivity() = 0;

    protected:
        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port)
        {
            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value , "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                          "the base class of channel MUST be UDPChannel or TCPChannel");

            constexpr bool is_udp = std::is_base_of<UDPChannel, T>::value;
            using endpoint_type = channel_type<is_udp>::endpoint;
            using socket_type   = channel_type<is_udp>::socket;
            try
            {
                std::auto_ptr<T> channel(new T);
                endpoint_type ep(boost::asio::ip::address::from_string(ip), port);
                if (ep.port())
                {
                    if (channel->BindSocket<socket_type, endpoint_type>(channel->Socket(), ep))
                    {
                        LOG_INFO("Candidate", "Channel Created[%s:%d]", ip.c_str(), port);
                        return channel.release();
                    }
                }
                LOG_ERROR("Candidate", "Create Channle Failed [%s] with random port", ip.c_str());
                return nullptr;
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Candidate", "CreateChannel exception %s",e.what());
                return nullptr;
            }
        }

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort)
        {
            assert(lowPort < upperPort);

            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            constexpr bool is_udp = std::is_base_of<UDPChannel, T>::value;
            using endpoint_type = channel_type<is_udp>::endpoint;
            using socket_type = channel_type<is_udp>::socket;

            try
            {
                std::auto_ptr<T> channel(new T);

                endpoint_type ep(boost::asio::ip::address::from_string(ip), 0);
                for (decltype(sMaxBindTimes) i = 0; i < sMaxBindTimes; ++i)
                {
                    if (channel->BindSocket<socket_type, endpoint_type>(channel->Socket(), ep))
                    {
                        LOG_INFO("Candidate", "Channel Created[%s:%d]", ip.c_str(), port);
                        return channel.release();
                    }
                }

                LOG_ERROR("Candidate", "Create Channle Failed [%s] with random port", ip.c_str());
                return nullptr;
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Candidate", "CreateChannel exception %s", e.what());
                return nullptr;
            }
        }

    protected:
        enum class InternalMsg {
            BindRequest,
            BindResp,
            BindErrResp,
            SSReq,
            SSResp,
            SSErrResp,
            Quit,
        };

    protected:
        bool Subscribe(InternalMsg msg, PG::Subscriber* subscriber);
        bool Unsubscribe(InternalMsg msg, PG::Subscriber* subscriber);
        bool Unsubscribe(PG::Subscriber* subscriber);

    protected:
        Channel *m_pChannel;

    private:
        static void RecvThread(Candidate* pThis);

    private:
        static const uint8_t sMaxBindTimes = 5;
        static const uint8_t sPacketCache = 128;

    private:
        std::thread          m_RecvThrd;
        std::atomic_bool     m_bQuit;
        std::recursive_mutex m_InternalMsgMutex;
        PG::Publisher        m_InternalMsgPub;
        PG::CircularBuffer<STUN::PACKET::stun_packet, 1, sPacketCache> m_Packets;
    };

    ////////////////////////////// Host Candidate //////////////////////////////
    class HostCandidate : public Candidate {
    public:
        using Candidate::Candidate;

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool Gather(const std::string&, uint16_t) override;
        virtual bool CheckConnectivity();
    };

    ////////////////////////////// ActiveCandidate //////////////////////////////
    class ActiveCandidate : public HostCandidate {
    public:
        using HostCandidate::HostCandidate;

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool CheckConnectivity();
    };

    ////////////////////////////// PassiveCandidate //////////////////////////////
    class PassiveCandidate : public HostCandidate {
    public:
        using HostCandidate::HostCandidate;

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool CheckConnectivity();
    };

    ////////////////////////////// SrflxCandidate //////////////////////////////
    class SrflxCandidate : public Candidate {
    public:
        using Candidate::Candidate;

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool Gather(const std::string& remote, uint16_t port) override;
        virtual bool CheckConnectivity();

    private:
        std::string m_SrflxIP;
        uint16_t    m_SrflxPort;
    };
}