#pragma once

#include "stundef.h"

#include <boost/asio.hpp>
#include <assert.h>

namespace STUN {

    template<class packet_type>
    class MessagePacket {
    public:
        MessagePacket(MsgIdentifier msgId) :
            m_attr_pos(0)
        {
            m_packet.MsgIdentifier(boost::asio::detail::socket_ops::host_to_network_short(static_cast<uint16_t>(msgId)));
        }

        ~MessagePacket()
        {
        }

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

    private:
        packet_type m_packet;
        uint16_t    m_attr_pos;
    };

    template<class packet_type, class protocol>
    class BindingRequestMsg : public MessagePacket<packet_type> {
    public:
        BindingRequestMsg(uint32_t priority) : MessagePacket(MsgIdentifier::BindingReq)
        {
            AddAttribute<protocol>(ATTR::Priority(boost::asio::detail::socket_ops::host_to_network_long(priority)))
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