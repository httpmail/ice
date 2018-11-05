#pragma once

#include "stundef.h"

#include <boost/asio.hpp>
#include <assert.h>
#include <type_traits>

using namespace boost::asio::detail::socket_ops;

namespace STUN {
    template<class protocol, MTU mtu>
    class MessagePacket : PACKET::StunPacket<mtu>{
    public:
        MessagePacket(MsgType msgId, const TransId& transId) :
            StunPacket(msgId, transId), m_AttrPos(0), m_PacketLen(0), m_FinalFlag(false)
        {
        }

        ~MessagePacket()
        {
        }

        bool IsTransIdEqual(const TransId& transId) const
        {
            return memcmp(transId, GetTransId(), sizeof(transId));
        }

        const uint8_t* GetData() const
        {
            assert(m_FinalFlag);
            return Data();
        }

        uint16_t GetLength() const 
        {
            return m_PacketLen + HeaderLength();
        }

        void AddAttribute(const ATTR::MappedAddress &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::ReflectedFrom &attr)
        {
            auto len = STUN::protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::ChangeRequest &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::ErrorCode &attr)
        {
            auto len = STUN::protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::UnknownAttributes &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::XorMappedAddress &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Software &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Realm &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Role &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_PacketLen += len;
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Nonce &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::AlternateServer &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::Priority &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_PacketLen += len;
            m_AttrPos += len;
        }

        void AddAttribute(const ATTR::UseCandidate &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

    protected:
        int16_t     m_PacketLen;
        uint16_t    m_AttrPos;
        bool        m_FinalFlag;
    };

    template<class protocol, MTU mtu = MTU::IPv4>
    class BindingRequestMsg : public MessagePacket<protocol, mtu> {
    public:
        BindingRequestMsg(uint32_t priority, const TransId &transId)
            : MessagePacket(MsgType::BindingRequest, transId)
        {
            AddAttribute(ATTR::Priority());
        }

        virtual ~BindingRequestMsg() {}
    };
}