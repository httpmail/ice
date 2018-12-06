#pragma once

#include <thread>
#include <stdint.h>

#include "pg_msg.h"
#include "pg_log.h"
#include "stundef.h"

namespace STUN {
    class SubBindRequestMsg;
}

namespace ICE {
    class Channel;

    class Candidate {
    public:
        enum class type_ref : uint8_t{
            /*5.1.2.2.  Guidelines for Choosing Type and Local Preferences*/
            server_reflexive = 100,
            relayed = 0,
            host = 126,
            peer_reflexive = 110,
        };
    public:
        Candidate(type_ref eTypeRef, uint8_t comp_id, uint16_t localRef, uint64_t tiebreaker);

        virtual ~Candidate();

    public:
        virtual bool Create(const std::string& local, uint16_t port) = 0;
        virtual bool Gather(const std::string& remote, uint16_t port) = 0;
        virtual bool CheckConnectivity(const std::string& remote, uint16_t port, const std::string& key, const std::string& username) = 0;

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
        using TimeOutInterval = std::vector<uint32_t>;

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
        bool ConnectivityCheck(const STUN::SubBindRequestMsg& bindMsg,
            const TimeOutInterval &timeout,
            const std::string& username,
            const std::string& password);

    protected:
        Channel       *m_pChannel;
        bool           m_bControlling;
        const type_ref m_TypeRef;
        const uint8_t  m_ComponentId;
        const uint16_t m_LocalRef;
        const uint32_t m_Priority;
        const uint64_t m_Tiebreaker;

    private:
        static void         RecvThread(Candidate* pThis);
        static uint32_t     FormulaPriority(type_ref type, uint32_t localPref, uint8_t comp_id)
        {
            return ((static_cast<uint8_t>(type) & 0xFF) << 24) + ((localPref & 0xFFFF) << 8) + (((256 - comp_id) & 0xFF) << 0);
        }

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
        HostCandidate(uint8_t comp_id, uint16_t localRef, uint64_t tiebreaker) : Candidate(type_ref::host, comp_id, localRef, tiebreaker) {}

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool Gather(const std::string&, uint16_t) override;
        virtual bool CheckConnectivity(const std::string& remote, uint16_t port, const std::string& key, const std::string& username) override;
    };

    ////////////////////////////// ActiveCandidate //////////////////////////////
    class ActiveCandidate : public HostCandidate {
    public:
        using HostCandidate::HostCandidate;

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool CheckConnectivity(const std::string& remote, uint16_t port, const std::string&key, const std::string& username) override;
    };

    ////////////////////////////// PassiveCandidate //////////////////////////////
    class PassiveCandidate : public HostCandidate {
    public:
        using HostCandidate::HostCandidate;

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool CheckConnectivity(const std::string& remote, uint16_t port, const std::string&key, const std::string& username) override;
    };

    ////////////////////////////// SrflxCandidate //////////////////////////////
    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(uint8_t comp_id, uint16_t localRef, uint64_t tiebreaker)
            : Candidate(type_ref::server_reflexive, comp_id, localRef, tiebreaker)
        {}

    public:
        virtual bool Create(const std::string& local, uint16_t port) override;
        virtual bool Gather(const std::string& remote, uint16_t port) override;
        virtual bool CheckConnectivity(const std::string& remote, uint16_t port, const std::string&key, const std::string& username) override;

    private:
        std::string m_SrflxIP;
        uint16_t    m_SrflxPort;
    };
}


namespace STUN {
    class Candidate {
    public:
        Candidate();
        virtual ~Candidate();

    private:
        const uint32_t m_PRI;
    };
}