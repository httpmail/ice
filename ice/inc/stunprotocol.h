#pragma once

#include "stundef.h"
#include <set>
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
