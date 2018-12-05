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
            m_StunPacket(msgId, transId), m_AttrLength(0), m_FinalFlag(false)
        {
        }

        MessagePacket(const PACKET::stun_packet& packet);

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

        bool HasAttribute(ATTR::Id id) const
        {
            return m_Attributes.find(id) != m_Attributes.end();
        }

        const ATTR::MappedAddress*    GetAttribute(const ATTR::MappedAddress*& mapAddr) const;
        const ATTR::ChangeRequest*    GetAttribute(const ATTR::ChangeRequest*& changeReq) const;
        const ATTR::XorMappedAddress* GetAttribute(const ATTR::XorMappedAddress*& xorMap) const;
        const ATTR::Role*             GetAttribute(const ATTR::Role*& role) const;
        const ATTR::Priority*         GetAttribute(const ATTR::Priority*& pri) const;
        const ATTR::UseCandidate*     GetAttribute(const ATTR::UseCandidate*& useCan) const;
        const ATTR::Software*         GetAttribute(const ATTR::Software*& software) const;
        const ATTR::Realm*            GetAttribute(const ATTR::Realm*& realm) const;
        const ATTR::Nonce*            GetAttribute(const ATTR::Nonce*& nonce) const;
        const ATTR::Password*         GetAttribute(const ATTR::Password*& pwd) const;
        const ATTR::UserName*         GetAttribute(const ATTR::UserName*& username) const;
        const ATTR::MessageIntegrity* GetAttribute(const ATTR::MessageIntegrity*& msgIntegrity) const;
        const ATTR::Fingerprint*      GetAttribute(const ATTR::Fingerprint*& figerprint) const;
        const ATTR::UnknownAttributes* GetAttribute(const ATTR::UnknownAttributes*& unknowAttrs) const;


        void AddAttribute(const ATTR::MappedAddress &attr);
        void AddAttribute(const ATTR::ChangeRequest &attr);
        void AddAttribute(const ATTR::XorMappedAddress &attr);
        void AddAttribute(const ATTR::Role &attr);
        void AddAttribute(const ATTR::Priority &attr);
        void AddPriority(uint32_t pri)
        {
            ATTR::Priority attr;
            attr.Pri(pri);
            AddAttribute(attr);
        }
        void AddAttribute(const ATTR::UseCandidate &attr);

        void AddSoftware(const std::string& desc);
        void AddRealm(const std::string& realm);
        void AddErrorCode(uint16_t clsCode, uint16_t number, const std::string& reason);
        void AddNonce(const std::string& nonce);
        void AddPassword(const std::string& password);
        void AddUsername(const std::string& username);
        void AddUnknownAttributes(std::vector<ATTR::Id> unknownattributes);

        static void GenerateRFC5389TransationId(TransIdRef id);
        static void GenerateRFC3489TransationId(TransIdRef id);
        static void ComputeSHA1(const MessagePacket &packet, const std::string& key, SHA1Ref sha1);
        static bool VerifyMsgIntegrity(const MessagePacket &packet, const std::string& key);

    protected:
        using Attributes = std::unordered_map<ATTR::Id, int16_t>; /*key = attribute id,  value = index in StunPacket::m_Attrs */

    protected:
        uint16_t CalcAttrEncodeSize(uint16_t contentSize, uint16_t& paddingSize, uint16_t header_size = 4) const;
        uint8_t* AllocAttribute(ATTR::Id id, uint16_t size);
        void     AddTextAttribute(ATTR::Id id, const void* data, uint16_t size);

    protected:
        uint16_t            m_AttrLength;
        bool                m_FinalFlag;
        PACKET::stun_packet m_StunPacket;
        Attributes          m_Attributes;
        Attributes          m_UnsupportedAttrs;
    };

    class BindingRequestMsg : public MessagePacket{
        using MessagePacket::MessagePacket;
    public:
        BindingRequestMsg(uint32_t priority, const TransId &transId)
            : MessagePacket(MsgType::BindingRequest, transId)
        {
        }
        virtual ~BindingRequestMsg() {}
    };

    class BindingRespMsg : public MessagePacket {
        using MessagePacket::MessagePacket;
    public:
        BindingRespMsg(const TransId &transId)
            : MessagePacket(MsgType::BindingResp, transId)
        {
        }
    };

    class BindingErrRespMsg : public MessagePacket {
        using MessagePacket::MessagePacket;
    public:
        BindingErrRespMsg(const TransId &transId)
            : MessagePacket(MsgType::BindingErrResp, transId)
        {
        }

        void SetAttribute(uint16_t class_code, uint16_t error_code, const std::string& reason)
        {
            AddErrorCode(class_code, error_code, reason);
        }
    };

    class SharedSecretReqMsg : public MessagePacket {
        using MessagePacket::MessagePacket;
    public:
        SharedSecretReqMsg(const TransId &transId)
            : MessagePacket(MsgType::SSRequest, transId)
        {
        }
    };

    class SharedSecretRespMsg : public MessagePacket {
        using MessagePacket::MessagePacket;
    public:
        SharedSecretRespMsg(const TransId &transId)
            : MessagePacket(MsgType::SSResponse, transId)
        {
        }
    };

    class SharedSecretErrRespMsg : public MessagePacket {
        using MessagePacket::MessagePacket;
    public:
        SharedSecretErrRespMsg(const TransId &transId)
            : MessagePacket(MsgType::SSResponse, transId)
        {
        }
    };


    class FirstBindRequestMsg : public MessagePacket {
    public:
        FirstBindRequestMsg(const TransId& transId) :
            MessagePacket(MsgType::BindingRequest, transId)
        {
        }

        virtual ~FirstBindRequestMsg() = 0 {}
    };

    class SubBindRequestMsg : public MessagePacket {
    public:
        SubBindRequestMsg(uint32_t pri, const TransId& transId, const ATTR::Role &role);
        virtual ~SubBindRequestMsg() = 0 {}
    };

    class BindRespMsg : public MessagePacket {
    public:
        BindRespMsg(const TransId& transId);
        virtual ~BindRespMsg() = 0 {}
    };

    class RFC53891stBindRequestMsg : public FirstBindRequestMsg {
    public:
        RFC53891stBindRequestMsg(const TransId& transId) :
            FirstBindRequestMsg(transId)
        {
            assert(PG::host_to_network(sMagicCookie) == reinterpret_cast<const uint32_t*>(transId)[0]);
        }
    };

    class RFC34891stBindRequestMsg : public FirstBindRequestMsg {
    public:
        using FirstBindRequestMsg::FirstBindRequestMsg;
    };

    class RFC5389SubBindReqMsg : public SubBindRequestMsg {
    public:
        using SubBindRequestMsg::SubBindRequestMsg;

        virtual ~RFC5389SubBindReqMsg() {}
    };
}