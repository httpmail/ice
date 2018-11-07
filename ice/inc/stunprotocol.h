#pragma once

#include "stundef.h"
#include <set>

#if 0
namespace STUN {

    class Message;
    namespace PROTOCOL{

        class RFC3489 {
        public:
            static uint16_t EncodeAttribute(const ATTR::MappedAddressAttr &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::ChangeRequestAttr &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::ErrorCodeAttr &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::UnknownAttributes &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::UsernameAttr &attr, uint8_t *buf);
            static uint16_t EncodeAttribute(const ATTR::MessageIntegrityAttr &attr, uint8_t *buf);
        };

        class RFC5389 {
        public:
            static uint16_t EncodeAttribute(const ATTR::MappedAddressAttr &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::ErrorCodeAttr &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::UnknownAttributes &attr, uint8_t* buf);
            static uint16_t EncodeAttribute(const ATTR::UsernameAttr &attr, uint8_t *buf);
            static uint16_t EncodeAttribute(const ATTR::XorMappedAddressAttr &attr, uint8_t *buf);
            static uint16_t EncodeAttribute(const ATTR::IceRoleAttr &attr, uint8_t *buf);
            static uint16_t EncodeAttribute(const ATTR::Priority &attr, uint8_t *buf);
            static uint16_t Finalize(const Message &message, uint8_t *attr_buf, uint16_t length);

            static void GenerateTransationId(uint8_t* transBuf, int16_t size);

        private:
            static uint16_t AddMessageIntegrityAttribute(uint8_t *buf);
            static uint16_t AddFingerprintAttribute(uint8_t *buf);

        private:
            static const uint32_t sCRC32Xord = 0x5354554e;
        };
    }
}
#endif

namespace STUN{
    namespace PROTOCOL {
        template<class protocol_version>
        class STUN_PROTOCOL {
        public:
            static uint16_t Encode(const ATTR::MappedAddress& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                // reserved
                buf[0] = 0;

                // family
                buf[1] = static_cast<uint8_t>(attr.Family());

                // port 
                reinterpret_cast<uint16_t*>(&buf[2])[0] = PG::host_to_network(attr.Port());

                // address
                reinterpret_cast<uint32_t*>(&buf[3])[0] = PG::host_to_network(attr.Address());

                return attr.Length() + header_size;
            }

            static uint16_t Encode(const ATTR::ChangeRequest& attr, uint8_t *buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                //reinterpret_cast<uint32_t*>(buf)[0] = PG::host_to_network(attr.Value());

                return attr.Length() + header_size;
            }

            static uint16_t Encode(const ATTR::UserName& attr, uint8_t *buf)
            {
            }

            static uint16_t Encode(const ATTR::Password& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::MessageIntegrity& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::ErrorCode &attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::UnknownAttributes& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::ReflectedFrom& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Realm& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Nonce& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::XorMappedAddress& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Software& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::AlternateServer& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Priority& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                reinterpret_cast<uint32_t*>(buf)[0] = PG::host_to_network(attr.Pri());
                return attr.Length() + header_size; // content + header length
            }

            static uint16_t Encode(const ATTR::UseCandidate& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                return attr.Length() + header_size;
            }

            static uint16_t Encode(const ATTR::Fingerprint& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Role& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                reinterpret_cast<uint64_t*>(buf)[0] = PG::host_to_network(attr.TieBreaker());
                return attr.Length() + header_size;
            }

            static void GenerateTransationId(STUN::TransId id)
            {
                for (int i = 0; i < sizeof(id) / sizeof(id[0]); ++i)
                    id[0] = PG::GenerateRandom<uint8_t>(0, 0xFF);
            }

        protected:
            static uint16_t EncodeHeader(const ATTR::Header& header, uint8_t* buf)
            {
                reinterpret_cast<uint16_t*>(buf)[0] = PG::host_to_network(static_cast<uint16_t>(header.Type()));
                reinterpret_cast<uint16_t*>(buf)[1] = PG::host_to_network(header.Length());

                return sizeof(header);
            }
        };

        class RFC3489 : private STUN_PROTOCOL<RFC3489> {
        public:
            static uint16_t Encode(const ATTR::ChangeRequest& attr, uint8_t* buf)
            {
                return STUN_PROTOCOL::Encode(attr, buf);
            }
        };

        class RFC5389 : private STUN_PROTOCOL<RFC5389> {
        public:
            static uint16_t Encode(const ATTR::Priority& attr, uint8_t* buf)
            {
                return STUN_PROTOCOL::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Role& attr, uint8_t* buf)
            {
                return STUN_PROTOCOL::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::UseCandidate& attr, uint8_t* buf)
            {
                return STUN_PROTOCOL::Encode(attr, buf);
            }

            static void GenerateTransationId(STUN::TransId id)
            {
                memcpy(id, &STUN::sMagicCookie, sizeof(sMagicCookie));

                for (uint16_t i = 4; i < STUN::sTransationLength; ++i)
                    id[i] = PG::GenerateRandom<uint8_t>(0, 0xFF);
            }
        };
    }
}