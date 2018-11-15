#include "stunmsg.h"

namespace {
    uint16_t CalcPaddingSize(uint16_t length, int16_t N = 4)
    {
        assert((!(N &(N - 1))) && N); // n MUST be 2^n
        return (length + N - 1) & (~(N - 1));
    }
}

namespace STUN {
    uint8_t * MessagePacket::AllocAttribute(ATTR::Id id, uint16_t size)
    {
        if (m_AttrLength + size > sizeof(m_StunPacket.Attributes()))
            return nullptr;

        assert(m_Attributes.find(id) == m_Attributes.end());
        m_Attributes[id] = m_AttrLength;
        auto pBuf = &m_StunPacket.Attributes()[m_AttrLength];
        m_AttrLength += size;
        return pBuf;
    }

    uint16_t MessagePacket::CalcAttrEncodeSize(uint16_t contentSize, uint16_t& paddingSize, uint16_t header_size /*= 4*/) const
    {
        paddingSize = CalcPaddingSize(contentSize);
        return paddingSize + contentSize + header_size;
    }

    void MessagePacket::AddTextAttribute(ATTR::Id id, const void* data, uint16_t size)
    {
        uint16_t padding_size = 0;
        auto total_size = CalcAttrEncodeSize(size, padding_size);
        auto pBuf =  AllocAttribute(id, total_size);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough Memory for TextAttribute [%d]", id);
            return ;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(id));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(size);
        pBuf += 4;

        memcpy(pBuf, data, size);
        if (padding_size)
        {
            memset(pBuf + size, 0, padding_size);
        }
    }

    void MessagePacket::AddAttribute(const ATTR::Priority &attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "Priority attribute already existed");
            return;
        }

        static_assert(sizeof(ATTR::Priority) == 8, "Priority Must be 8 bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(attr));

        assert(pBuf);

        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(&attr)[0];
    }

    void MessagePacket::AddAttribute(const ATTR::UseCandidate & attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "UseCandidate attribute already existed");
            return;
        }

        // UseCandidate has no content
        static_assert(sizeof(ATTR::UseCandidate) == sizeof(ATTR::Header), "UseCandidate has no content");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::UseCandidate));
        assert(pBuf);
        m_Attributes[attr.Type()] = m_AttrLength;
        reinterpret_cast<uint32_t*>(pBuf)[0] = reinterpret_cast<const uint32_t*>(&attr)[0];
    }

    MessagePacket::MessagePacket(const PACKET::stun_packet & packet) :
        m_StunPacket(packet), m_FinalFlag(true)
    {
        assert(packet.MsgId() != MsgType::InvalidMsg);
        m_AttrLength = packet.Length();

        try
        {
            auto attr         = packet.Attributes();
            auto content_len  = packet.Length();
            uint16_t attr_len = 0;

            for(decltype(content_len) i = 0 ; i < content_len;  i += attr_len + sizeof(ATTR::Header))
            {
                ATTR::Id id = static_cast<ATTR::Id>(PG::network_to_host(reinterpret_cast<const uint16_t*>(&attr[i])[0]));
                attr_len    = PG::network_to_host(reinterpret_cast<const uint16_t*>(&attr[i])[1]);

                switch (id)
                {
                case STUN::ATTR::Id::MappedAddress:
                case STUN::ATTR::Id::RespAddress:
                case STUN::ATTR::Id::ChangeRequest:
                case STUN::ATTR::Id::SourceAddress:
                case STUN::ATTR::Id::ChangedAddress:
                case STUN::ATTR::Id::Username:
                case STUN::ATTR::Id::Password:
                case STUN::ATTR::Id::MessageIntegrity:
                case STUN::ATTR::Id::ErrorCode:
                case STUN::ATTR::Id::UnknownAttributes:
                case STUN::ATTR::Id::ReflectedFrom:
                case STUN::ATTR::Id::Realm:
                case STUN::ATTR::Id::Nonce:
                case STUN::ATTR::Id::XorMappedAddress:
                case STUN::ATTR::Id::Software:
                case STUN::ATTR::Id::AlternateServer:
                case STUN::ATTR::Id::Priority:
                case STUN::ATTR::Id::UseCandidate:
                case STUN::ATTR::Id::Fingerprint:
                case STUN::ATTR::Id::IceControlled:
                case STUN::ATTR::Id::IceControlling:
                    m_Attributes[id] = i;
                    break;

                default:
                    m_UnsupportedAttrs[id] = i;
                    LOG_WARNING("STUN-MSG", "Unsupported attribute [0x%x]", id);
                    break;
                }
            }
        }
        catch (const std::exception&)
        {

        }
    }

    void MessagePacket::AddAttribute(const ATTR::MappedAddress &attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "MappedAddress[%d] attribute already existed!", attr.Type());
            return;
        }

        static_assert(sizeof(ATTR::MappedAddress) == 12, "MappedAddress MUST be 12 bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::MappedAddress));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for Attribute [%d]", attr.Type());
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);

        reinterpret_cast<uint64_t*>(pBuf)[0]     = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[4])[0] = reinterpret_cast<const uint32_t*>(&source[4])[0];
    }

    void MessagePacket::AddAttribute(const ATTR::ChangeRequest & attr)
    {
        static_assert(sizeof(ATTR::ChangeRequest) == 8, "sizeof(ChangeRequest) Must Be 8 bytes");

        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "ChangeRequest already existed");
            return;
        }

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::ChangeRequest));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough Memory for ChangeRequest");
            return;
        }

        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(&attr)[0];
    }

    void MessagePacket::AddAttribute(const ATTR::XorMappedAddress &attr)
    {
        static_assert(sizeof(ATTR::XorMappedAddress) == 12, "XorMappedAddress Must Be 12 Bytes");

        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "XorMappedAddress attributes already existed!");
            return;
        }

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::XorMappedAddress));

        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for XorMappedAddress");
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);
        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[4])[0] = reinterpret_cast<const uint32_t*>(&source[4])[0];
    }

    void MessagePacket::AddAttribute(const ATTR::Role &attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "Role attribute already existed!");
            return;
        }

        static_assert(sizeof(ATTR::Role) == 12, "Role Attribute Must Be 12 Bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::Role));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for Role");
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);
        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[4])[0] = reinterpret_cast<const uint32_t*>(&source[4])[0];
    }

    void MessagePacket::AddSoftware(const std::string& desc)
    {
        assert(desc.length() < ATTR::sTextLimite);
        AddTextAttribute(ATTR::Id::Software, desc.data(), static_cast<uint16_t>(desc.length()));
    }

    void MessagePacket::AddRealm(const std::string& realm)
    {
        assert(realm.length() < ATTR::sTextLimite);

        //AddTextAttribute(ATTR::Id::Realm, realm.data(), realm.length());
    }

    void MessagePacket::AddErrorCode(uint16_t clsCode, uint16_t number, const std::string& reason)
    {
        assert(reason.length() < ATTR::sTextLimite);
        uint16_t padding_size = 0;
        uint16_t reason_length = static_cast<uint16_t>(reason.length());

        auto size = CalcPaddingSize(reason_length, padding_size);

        // ErrorCode attribute size = HEADER + 4 bytes + reason
        auto pBuf = AllocAttribute(ATTR::Id::ErrorCode, size + sizeof(ATTR::Header) + 4);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough memory for ErrorCode");
            return;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::ErrorCode));
        // error code length = reason length + 4 bytes
        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(reason_length + 4));

        ATTR::ErrorCode *pErrorCode = reinterpret_cast<ATTR::ErrorCode*>(pBuf);
        pErrorCode->Class(clsCode);
        pErrorCode->Number(number);

        memcpy(pBuf + 4 + reason_length, 0, padding_size);
    }

    void MessagePacket::AddNonce(const std::string& nonce)
    {
        assert(nonce.length() < ATTR::sTextLimite);

        //AddTextAttribute(ATTR::Id::Nonce, nonce.data(), nonce.length());
    }

    void MessagePacket::AddPassword(const std::string& password)
    {
        assert(password.length() < ATTR::sTextLimite);

        AddTextAttribute(ATTR::Id::Password, password.data(), static_cast<uint16_t>(password.length()));
    }

    void MessagePacket::AddUsername(const std::string& username)
    {
        assert(username.length() < ATTR::sUsernameLimite);

        AddTextAttribute(ATTR::Id::Username, username.data(), static_cast<uint16_t>(username.length()));
    }

    void MessagePacket::AddUnknownAttributes(std::vector<ATTR::Id> unknownattributes)
    {
        if (HasAttribute(ATTR::Id::UnknownAttributes))
        {
            LOG_WARNING("STUN-MSG", "unknownAttribute already existed!");
            return;
        }

        uint16_t cnt = static_cast<uint16_t>(unknownattributes.size());
        uint16_t content_size = cnt * sizeof(ATTR::Id);
        auto size = CalcPaddingSize(content_size);

        auto pBuf = AllocAttribute(STUN::ATTR::Id::UnknownAttributes, size + content_size + 4);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough for unknownattribute");
            return;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::UnknownAttributes));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(content_size);

        pBuf += 4;
        for (uint16_t i = 0; i < cnt; ++i)
        {
            reinterpret_cast<uint16_t*>(pBuf)[i] = PG::host_to_network(static_cast<uint16_t>(unknownattributes[i]));
        }
    }

    void MessagePacket::GenerateRFC5389TransationId(TransIdRef id)
    {
        static_assert(sizeof(id) == sTransationLength, "the length of Transation Id is ");

        reinterpret_cast<uint32_t*>(id)[0] = PG::host_to_network(sMagicCookie);
        reinterpret_cast<uint32_t*>(&id[4])[0] = PG::host_to_network(PG::GenerateRandom32());
        reinterpret_cast<uint64_t*>(&id[8])[0] = PG::host_to_network(PG::GenerateRandom64());
    }

    void MessagePacket::GenerateRFC3489TransationId(TransIdRef id)
    {
        static_assert(sizeof(id) == sTransationLength, "the length of Transation Id is ");
        reinterpret_cast<uint64_t*>(&id)[0] = PG::host_to_network(PG::GenerateRandom64());
        reinterpret_cast<uint64_t*>(&id)[1] = PG::host_to_network(PG::GenerateRandom64());
    }

    ///////////////////////// Subsequent Bind Request Message ///////////////////////////////////
    SubBindRequestMsg::SubBindRequestMsg(uint32_t pri, const TransId & transId, const ATTR::Role &role) :
        MessagePacket(MsgType::BindingRequest, transId)
    {
        ATTR::Priority Pri;
        Pri.Pri(pri);

        AddAttribute(Pri);
        AddAttribute(role);
    }

    ///////////////////////// Bind Resp Message //////////////////////////////////////////////////
    BindRespMsg::BindRespMsg(const TransId& transId) :
        MessagePacket(MsgType::BindingResp,transId)
    {
    }
}

