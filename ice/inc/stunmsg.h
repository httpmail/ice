#pragma once

#include "stundef.h"

#include <boost/asio.hpp>
#include <assert.h>
#include <type_traits>

using namespace boost::asio::detail::socket_ops;

namespace STUN {
    template<class header_type, class protocol, MTU mtu, class packet = PACKET::StunPacket<header_type, mtu> >
    class MessagePacket {
    public:
        MessagePacket(MsgType msgId, const TransId& transId) :
            m_Packet(msgId, transId), m_AttrPos(0), m_PacketLen(0), m_FinalFlag(false)
        {
#if 0
            static_assert(!std::is_pointer<packet_type>::value && std::is_same<PACKET::udp_stun_packet, packet_type>::value
                || std::is_same<PACKET::tcp_stun_packet, packet_type>::value,"packet_type cannot be pointer and MUST be \'udp_stun_packet\' or \'tcp_stun_packet'!");
#endif
        }

        ~MessagePacket()
        {
        }

        const uint8_t* GetData() const
        {
            assert(m_FinalFlag);
            return reinterpret_cast<const uint8_t*>(&m_Packet);
        }

        uint16_t GetLength() const 
        {
            return m_PacketLen + m_Packet.HeaderLength();
        }

        void AddAttribute(const ATTR::MappedAddress &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::ReflectedFrom &attr)
        {
            auto len = STUN::protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::ChangeRequest &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::ErrorCode &attr)
        {
            auto len = STUN::protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::UnknownAttributes &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::XorMappedAddress &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Software &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Realm &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Role &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_PacketLen += len;
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Nonce &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::AlternateServer &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Priority &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_PacketLen += len;
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::UseCandidate &attr)
        {
            auto len = protocol::Encode(attr, &m_Packet.Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

    protected:
        packet      m_Packet;
        int16_t     m_PacketLen;
        uint16_t    m_AttrPos;
        bool        m_FinalFlag;
    };

    template<class header_type, class protocol, MTU mtu = MTU::IPv4>
    class BindingRequestMsg : public MessagePacket<header_type, protocol, mtu> {
    public:
        BindingRequestMsg(uint32_t priority, const TransId &transId)
            : MessagePacket(MsgType::BindingRequest, transId)
        {
            AddAttribute(ATTR::Priority());
        }

        virtual ~BindingRequestMsg() {}
    };
}