#pragma once

#include "stundef.h"

#include <boost/asio.hpp>
#include <assert.h>
#include <type_traits>

using namespace boost::asio::detail::socket_ops;

namespace STUN {
    template<class packet_type>
    class MessagePacket {
    public:
        MessagePacket(MsgIdentifier msgId) :
            m_attr_pos(0), m_packet_length(0), m_final_flag(false)
        {
            static_assert(!std::is_pointer<packet_type>::value && std::is_same<PACKET::udp_stun_packet, packet_type>::value
                || std::is_same<PACKET::tcp_stun_packet, packet_type>::value,"packet_type cannot be pointer and MUST be \'udp_stun_packet\' or \'tcp_stun_packet'!");

            //assert(transation && size == sTransationLen);

            //memcpy(m_packet._transation, transation, size);
            m_packet.MsgIdentifier(boost::asio::detail::socket_ops::host_to_network_short(static_cast<uint16_t>(msgId)));
        }

        ~MessagePacket()
        {
        }

        const uint8_t* GetData() const { return reinterpret_cast<const uint8_t*>(&m_packet); }
        uint16_t GetLength() const { return m_packet_length + m_packet.HeaderLength();}

        template<class protocol>
        void AddAttribute(const ATTR::MappedAddressAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::RespAddressAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ChangedAddressAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ReflectedFromAttr &attr)
        {
            auto len = STUN::protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::SourceAddressAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ChangeRequestAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ErrorCodeAttr &attr)
        {
            auto len = STUN::protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::UnknownAttributes &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::XorMappedAddressAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Software &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Realm &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::IceRoleAttr &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_packet_length += len;
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Nonce &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::AlternateServer &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Priority &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_packet_length += len;
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::UseCandidate &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::IceControlled &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::IceControlling &attr)
        {
            auto len = protocol::EncodeAttribute(attr, &m_packet._attr[m_attr_pos]);
            m_attr_pos += len;
        }

        void Finalize()
        {
            m_final_flag = true;
            m_packet.PacketLength(host_to_network_short(m_packet_length));
        }

    protected:
        packet_type m_packet;
        int16_t     m_packet_length;
        uint16_t    m_attr_pos;
        bool        m_final_flag;
    };

    template<class packet_type, class protocol>
    class BindingRequestMsg : public MessagePacket<packet_type> {
    public:
        BindingRequestMsg(uint32_t priority) : MessagePacket(MsgIdentifier::BindingReq)
        {
            protocol::GenerateTransationId(m_packet._transation, sizeof(m_packet._transation));
            AddAttribute<protocol>(ATTR::Priority(boost::asio::detail::socket_ops::host_to_network_long(priority)));
        }

        BindingRequestMsg(uint32_t priority, const uint8_t* transationId, int16_t size)
            : MessagePacket(MsgIdentifier::BindingReq)
        {
            assert(transationId && size == sTransationLen);
            memcpy(m_packet._transation, transationId, size);
            AddAttribute<protocol>(ATTR::Priority(boost::asio::detail::socket_ops::host_to_network_long(priority)));
        }

        virtual ~BindingRequestMsg() {}
    };

    template<class packet_type, class protocol>
    class BindingRespMsg : public MessagePacket<packet_type> {
    public:
        BindingRespMsg() : MessagePacket(MsgIdentifier::BindingResp)  {}
        virtual ~BindingRespMsg() {}
    };

    template<class packet_type,class protocol>
    class BindErrRespMsg : public MessagePacket<packet_type> {
    public:
        BindErrRespMsg() : MessagePacket(MsgIdentifier::BindingErrResp) {}
        virtual ~BindErrRespMsg() {}
    };
}