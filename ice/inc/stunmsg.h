#pragma once

#include "pg_log.h"
#include "stundef.h"

#include <boost/asio.hpp>
#include <type_traits>
#include <unordered_map>
#include <assert.h>


using namespace boost::asio::detail::socket_ops;

namespace STUN {
    class MessagePacket {
    public:
        MessagePacket(MsgType msgId, const TransId& transId):
            m_StunPacket(msgId), m_AttrLength(0), m_FinalFlag(false)
        {
        }

        ~MessagePacket()
        {
        }

        bool IsTransIdEqual(TransIdConstRef transId) const
        {
            return 0 == memcmp(transId, m_StunPacket.TransId(), sizeof(transId));
        }

        bool IsTransIdEqual(const MessagePacket& other) const
        {
            return 0 == memcmp(other.m_StunPacket.TransId(), m_StunPacket.TransId(), sizeof(m_StunPacket.TransId()));
        }

        const uint8_t* GetData() const
        {
            return reinterpret_cast<const uint8_t*>(&m_StunPacket);
        }

        uint16_t GetLength() const 
        {
            return m_AttrLength + sStunHeaderLength;
        }

        const ATTR::Header* GetAttributes(ATTR::Id id) const
        {
            auto itor = m_Attributes.find(id);
            return itor == m_Attributes.end() ? nullptr : reinterpret_cast<const ATTR::Header*>(&m_StunPacket.Attributes()[itor->second]);
        }

        bool HasAttribute(ATTR::Id id) const
        {
            return m_Attributes.find(id) != m_Attributes.end();
        }

        template<class protocol>
        void AddAttribute(const ATTR::MappedAddress &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "MappedAddress attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ReflectedFrom &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "ReflectedFrom attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ChangeRequest &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "ChangeRequest attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ErrorCode &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "ErrorCode attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::UnknownAttributes &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "UnknownAttributes attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::XorMappedAddress &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "XorMappedAddress attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Software &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "Software attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Realm &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "Realm attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Role &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "Role attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Nonce &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "Nonce attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::AlternateServer &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "AlternateServer attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Priority &attr)
        {
            if (HasAttribute(attr.Type()))
            {
                LOG_WARNING("STUN-MSG", "Priority attributes already existed!");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::UseCandidate &attr)
        {
            auto itor = m_Attributes.find(attr.Type());
            if (itor != m_Attributes.end())
            {
                LOG_WARNING("STUNMSG", "UseCandidate attribute already existed");
                return;
            }

            m_Attributes[attr.Type()] = m_AttrLength;
            auto len = protocol::Encode(attr, (uint8_t*)&m_StunPacket.Attributes()[m_AttrLength]);
            m_AttrLength += len;
        }

    protected:
        using Attributes = std::unordered_map<ATTR::Id, int16_t>; /*key = attribute id,  value = index in StunPacket::m_Attrs */

    protected:
        uint16_t            m_AttrLength;
        bool                m_FinalFlag;
        PACKET::stun_packet m_StunPacket;
        Attributes          m_Attributes;
    };

    class BindingRequestMsg : public MessagePacket{
    public:
        BindingRequestMsg(uint32_t priority, const TransId &transId)
            : MessagePacket(MsgType::BindingRequest, transId)
        {
        }

        virtual ~BindingRequestMsg() {}
    };

    class BindingRequestMsg1st : public MessagePacket {
    public:
        using MessagePacket::MessagePacket;

    };

    class SubBindingRequestMsg : public MessagePacket {
        using MessagePacket::MessagePacket;
    };

    class BindRespMsg : public MessagePacket {
    };
}