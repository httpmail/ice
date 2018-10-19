#pragma once

#include <stdint.h>

namespace STUN {

    static const uint32_t sMagicCookie  = 0x2112A442;
    static const int sIPv4PathMTU       = 548;
    static const int sIPv6PathMTU       = 1280;

    enum class ErrorCode : uint16_t{
        BadReq                  = 404,
        Unauthorized            = 401,
        UnknownAttribute        = 420,
        StaleCredentials        = 430,
        IntegrityCheckFailure   = 431,
        MissingUsername         = 432,
        UseTLS                  = 433,
        ServerError             = 500,
        GlobalFailure           = 600,
    };

    enum class MsgIdentifier : uint16_t{
        BindingReq      = 0x0001,
        BindingResp     = 0x0101,
        BindingErrResp  = 0x0111,
        SSRequest       = 0x0002,
        SSResponse      = 0x0102,
        SSErrResp       = 0x1102,
    };

    enum class AddressFamily : uint8_t{
        IPv4 = 0x01,
        IPv6 = 0x02,
    };

    /*RFC5245 15.4.*/
    enum class  UFRAGAttrLimit : uint16_t /* in character */{
        Upper = 256,
        Lower = 4,
    };

    enum class PWDAttrLimit : uint16_t /* in character */ {
        Upper = 256,
        Lower = 22,
    };

    namespace ATTR
    {

        enum class Identifier : uint16_t {
            MappedAddress = 0x0001,
            RespAddress = 0x0002,
            ChangeReq = 0x0003,
            SourceAddress = 0x0004,
            ChangedAddress = 0x0005,
            Username = 0x0006,
            Password = 0x0007,

            MessageIntegrity = 0x0008,
            ErrorCode = 0x0009,

            UnknownAttributes = 0x000A,
            ReflectedFrom = 0x000B,

            Realm = 0x0014,
            Nonce = 0x0015,

            XorMappedAddress = 0x0020,

            Software = 0x8022,
            AlternateServer = 0x8023,
            Fingerprint = 0x8028,
        };

        struct  stun_attr_header {
        public:
            stun_attr_header(Identifier id) : _id(static_cast<uint16_t>(id)) {}
            stun_attr_header(uint16_t id) :   _id(id) {}
            uint16_t    Id()         const { return _id; }
            Identifier  identifier() const { return static_cast<Identifier>(_id); }
            uint16_t    Length()     const { return _length; }
            void        Length(uint16_t length) { _length = length; }

        protected:
            uint16_t _id;
            uint16_t _length;
        };

        struct MappedAddressAttr : stun_attr_header {
        public:
            MappedAddressAttr(Identifier id = Identifier::MappedAddress) :
                stun_attr_header(id),
                _reserved(0)
            {}

            uint8_t     Family()  const { return _family; }
            void        Family(uint8_t family) { _family = family; }

            uint16_t    Port()          const { return _port;   }
            void        Port(uint16_t port) { _port = port; }

            uint32_t    Address()       const { return _address;}
            void        Address(uint32_t address) { _address = address; }

        private:
            uint8_t     _reserved;
            uint8_t     _family;
            uint16_t    _port;
            uint32_t    _address;
        };

        /*
        RFC3489 support RESPONSE-ADDRESS, CHANGED-ADDRESS,
        CHANGE-REQUEST, SOURCE-ADDRESS, and REFLECTED-FROM attributes,
        and RFC53489 removed them.
        */
        struct RespAddressAttr : MappedAddressAttr {
            RespAddressAttr() : 
                MappedAddressAttr(Identifier::RespAddress)
            {}
        };

        struct ChangedAddressAttr : MappedAddressAttr {
            ChangedAddressAttr() : MappedAddressAttr(Identifier::ChangedAddress) {}
        };

        struct ReflectedFromAttr : MappedAddressAttr {
            ReflectedFromAttr() : MappedAddressAttr(Identifier::ReflectedFrom) {}
        };

        struct SourceAddressAttr : MappedAddressAttr {
            SourceAddressAttr() : MappedAddressAttr(Identifier::SourceAddress) {}
        };

        struct ChangeRequestAttr : stun_attr_header {
        public:
            ChangeRequestAttr() : stun_attr_header(Identifier::ChangeReq) {}
            uint32_t value() const { return _value; }

        private:
            uint32_t _value;
        };

        struct MessageIntegrityAttr : stun_attr_header {
        public:
            MessageIntegrityAttr() : stun_attr_header(Identifier::MessageIntegrity) {}

            const uint8_t* Hmac() const { return _hamc; }

        private:
            uint8_t _hamc[20];
        };

        struct ErrorCodeAttr : stun_attr_header {
            ErrorCodeAttr() : stun_attr_header(Identifier::ErrorCode) {}

            union {
                struct
                {
                    uint8_t : 8;
                    uint8_t : 8;
                    uint8_t : 3;
                    uint8_t  _class  : 3;
                    uint8_t  _number : 8;
                }detail;
                uint32_t _value;
            };
            uint8_t _reason[0];
        };

        struct UnknownAttributes : stun_attr_header {
            UnknownAttributes() : stun_attr_header(Identifier::UnknownAttributes) {}

            uint16_t _first_attr_id[0];
        };

        struct UsernameAttr : stun_attr_header{
            UsernameAttr() : stun_attr_header(Identifier::Username) {}
            uint8_t _text[0];
        };

        /*
        * RFC5389 added XOR-MAPPED-ADDRESS attribute, which is included in
        * Binding responses if the magic cookie is present in the request.
        * Otherwise, the RFC 3489 behavior is retained (that is, Binding
        * response includes MAPPED-ADDRESS)
        */
        struct XorMappedAddressAttr : MappedAddressAttr {
            XorMappedAddressAttr() : MappedAddressAttr(Identifier::XorMappedAddress) {}
        };

        /*
        * RFC5389 added
        */
        struct Fingerprint : stun_attr_header {
            Fingerprint() : stun_attr_header(Identifier::Fingerprint) {}

            uint32_t _crc32;
        };

        struct Software : stun_attr_header {
            Software() : stun_attr_header(Identifier::Software) {}
            uint8_t _text[0];
        };

        struct Realm : stun_attr_header {
            Realm() : stun_attr_header(Identifier::Realm) {}
        };

        struct Nonce : stun_attr_header {
            Nonce() : stun_attr_header(Identifier::Nonce) {}

            uint8_t _value[128];
        };

        struct AlternateServer : MappedAddressAttr {
            AlternateServer() : MappedAddressAttr(Identifier::AlternateServer) {}
        };
    }

    namespace PACKET{
        struct udp_stun_packet_header {
            uint16_t HeaderLength() const { return sizeof(udp_stun_packet_header); }
            uint16_t _id;
            uint16_t _length;
            uint8_t  _transation[16];
        };

        struct tcp_stun_packet_header {
            uint16_t HeaderLength() const { return sizeof(tcp_stun_packet_header); }
            uint16_t _framing;
            uint16_t _id;
            uint16_t _length;
            uint8_t  _transation[16];
        };

        struct udp_v4_stun_packet : public udp_stun_packet_header {
            uint8_t _attr[sIPv4PathMTU];
        };

        struct upd_v6_stun_packet : public udp_stun_packet_header {
            uint8_t _attr[sIPv6PathMTU];
        };

        struct tcp_v4_stun_packet : public tcp_stun_packet_header {
            uint8_t _attr[sIPv4PathMTU];
        };

        struct tcp_v6_stun_packet : public tcp_stun_packet_header {
            uint8_t _attr[sIPv6PathMTU];
        };
    }
}