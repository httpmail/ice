#pragma once

#include "pg_log.h"
#include "stundef.h"

#include <boost/asio.hpp>
#include <type_traits>
#include <unordered_map>
#include <assert.h>


using namespace boost::asio::detail::socket_ops;

namespace STUN {
    class MessagePacket : PACKET::StunPacket{
    public:
        MessagePacket(MsgType msgId, const TransId& transId) :
            StunPacket(msgId, transId), m_AttrPos(0), m_PacketLen(0), m_FinalFlag(false)
        {
        }

        ~MessagePacket()
        {
        }

        bool IsTransIdEqual(TransIdConstRef transId) const
        {
            return 0 == memcmp(transId, GetTransId(), sizeof(transId));
        }

        bool IsTransIdEqual(const MessagePacket& other) const
        {
            return 0;
        }

        const uint8_t* GetData() const
        {
            //assert(m_FinalFlag);
            return Data();
        }

        uint16_t GetLength() const 
        {
            return m_PacketLen + HeaderLength();
        }

        template<class protocol>
        void AddAttribute(const ATTR::MappedAddress &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ReflectedFrom &attr)
        {
            auto len = STUN::protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ChangeRequest &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::ErrorCode &attr)
        {
            auto len = STUN::protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::UnknownAttributes &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::XorMappedAddress &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Software &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Realm &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Role &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_PacketLen += len;
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Nonce &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::AlternateServer &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

        template<class protocol>
        void AddAttribute(const ATTR::Priority &attr)
        {
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_PacketLen += len;
            m_AttrPos += len;
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

            m_Attributes[attr.Type()] = m_AttrPos;
            auto len = protocol::Encode(attr, &Attributes()[m_AttrPos]);
            m_AttrPos += len;
        }

    protected:
        using Attributes = std::unordered_map<ATTR::Id, int16_t>; /*key = attribute id,  value = index in StunPacket::m_Attrs */

    protected:
        int16_t              m_PacketLen;
        uint16_t             m_AttrPos;
        bool                 m_FinalFlag;
        PACKET1::stun_packet m_StunPacket;
        Attributes           m_Attributes;
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