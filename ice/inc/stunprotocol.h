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
            static uint16_t Encode(const ATTR::MappedAddress& mapAddress, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::ChangeRequest& changeReq, uint8_t *buf) { return 0; }
            static uint16_t Encode(const ATTR::UserName& userName, uint8_t *buf) { return 0; }
            static uint16_t Encode(const ATTR::Password& password, uint8_t *buf) { return 0; }
            static uint16_t Encode(const ATTR::MessageIntegrity& msgIntegrity, uint8_t *buf) { return 0; }
            static uint16_t Encode(const ATTR::ErrorCode &errCode, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::UnknownAttributes& unknown, uint8_t *buf) { return 0; }
            static uint16_t Encode(const ATTR::ReflectedFrom& reflected, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::Realm& realm, uint8_t *buf) { return 0; }
            static uint16_t Encode(const ATTR::Nonce& nonce, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::XorMappedAddress& xorMap, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::Software& software, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::AlternateServer& alternate, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::Priority& priority, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::UseCandidate& useCand, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::Fingerprint& fingerprint, uint8_t* buf) { return 0; }
            static uint16_t Encode(const ATTR::Role& role, uint8_t* buf) { return 0; }
        };

        class RFC3489 : public STUN_PROTOCOL<RFC3489> {
        };

        class RFC5389 : public STUN_PROTOCOL<RFC5389> {
        };
    }
}