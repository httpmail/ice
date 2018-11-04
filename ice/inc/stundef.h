#pragma once

#include <stdint.h>
#include <boost/asio.hpp>
#pragma warning (disable:4200)

namespace STUN {
    static const uint32_t sMagicCookie      = boost::asio::detail::socket_ops::host_to_network_long(0x2112A442);
    static const uint16_t sIPv4PathMTU      = 548;
    static const uint16_t sIPv6PathMTU      = 1280;
    static const uint16_t sTransationLength = 16;
    static const uint16_t sStunHeaderLength = 20;
    using TransId = uint8_t[sTransationLength];

    enum class AgentRole : uint8_t{
        Controlling = 0,
        Controlled = 1
    };

    enum class ErrorCode : uint16_t {
        BadRequest              = 404,
        Unauthorized            = 401,
        UnknownAttribute        = 420,
        StaleCredentials        = 430,
        IntegrityCheckFailure   = 431,
        MissingUsername         = 432,
        UseTLS                  = 433,
        ServerError             = 500,
        GlobalFailure           = 600,
    };

    enum class MsgType : uint16_t {
        BindingRequest  = 0x0001,
        BindingResp     = 0x0101,
        BindingErrResp  = 0x0111,
        SSRequest       = 0x0002,
        SSResponse      = 0x0102,
        SSErrResp       = 0x1102,
    };

    enum class AddressFamily : uint8_t {
        IPv4 = 0x01,
        IPv6 = 0x02,
    };

    enum class MTU {
        IPv4 = 548,
        IPv6 = 1280
    };

    namespace ATTR {

        /*RFC5245 15.4.*/
        enum class  UFRAGLimit : uint16_t /* in character */ {
            Upper = 256,
            Lower = 4,
        };

        enum class PasswordLimit : uint16_t /* in character */ {
            Upper = 256,
            Lower = 22,
        };

        enum class Id {
            MappedAddress   = 0x0001,
            RespAddress     = 0x0002,
            ChangeRequest   = 0x0003,
            SourceAddress   = 0x0004,
            ChangedAddress  = 0x0005,
            Username        = 0x0006,
            Password        = 0x0007,

            MessageIntegrity  = 0x0008,
            ErrorCode         = 0x0009,

            UnknownAttributes = 0x000A,
            ReflectedFrom     = 0x000B,

            Realm = 0x0014,
            Nonce = 0x0015,

            XorMappedAddress = 0x0020,

            Software        = 0x8022,
            AlternateServer = 0x8023,
            Priority        = 0x0024, /* RFC8445 16.1 */
            UseCandidate    = 0x0025, /* RFC8445 16.1 */
            Fingerprint     = 0x8028,
            IceControlled   = 0x8029, /* RFC8445 16.1 */
            IceControlling  = 0x802A, /* RFC8445 16.1 */
        };

        ////////////////////// attribute ////////////////////////////////
        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Type                  |            Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             Value                             ....
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */
        class Header {
        public:
            explicit Header(Id type, uint16_t length) :
                m_type(static_cast<uint16_t>(type)),m_length(length)
            {
            }

            uint16_t Length() const 
            {
                return m_length;
            }

            void Length(uint16_t length)
            {
                m_length = length;
            }

            Id Type() const
            {
                return static_cast<Id>(boost::asio::detail::socket_ops::network_to_host_short(m_type));
            }

        protected:
            uint16_t m_type;
            uint16_t m_length;
        };

        class MappedAddress : public Header{
        public:
            MappedAddress(Id id = Id::MappedAddress) :
                Header(id, 8)
            {}

            uint8_t              : 8; // reserved
            uint8_t     m_Family : 8; // family
            uint16_t    m_Port   : 16;// port
            uint32_t    m_Address: 32;
        };

        class ResponseAddress : public MappedAddress {
        public:
            ResponseAddress() :
                MappedAddress(Id::RespAddress)
            {}
        };

        class ChangeRequest : public Header {
        public:
            ChangeRequest(bool changeIP) :
                Header(Id::ChangeRequest, 4), m_ChangeIp(changeIP),m_ChangePort(changeIP)
            {}

            uint32_t : 29; // reserved
            uint32_t m_ChangeIp   : 1;
            uint32_t m_ChangePort : 1;
            uint32_t : 1;// reserved
        };

        class SourceAddress : public MappedAddress {
        public:
            SourceAddress() :
                MappedAddress(Id::SourceAddress)
            {}
        };

        class ChangedAddress : public Header {
        public:
            ChangedAddress() :
                Header(Id::ChangedAddress, 0)
            {}
        };

        class UserName : public Header {
        public:
            UserName() :
                Header(Id::Username, 0)
            {}

        private:
            uint8_t m_Value[0]; //
        };

        class Password : public Header {
        public:
            Password() :
                Header(Id::Password, 0)
            {}

        private:
            uint8_t m_Value[0];
        };

        class MessageIntegrity : public Header {
        public:
            MessageIntegrity() :
                Header(Id::MessageIntegrity, 20)
            {}

        private:
            uint8_t m_SHA1[20];
        };

        class ErrorCode : public Header {
        public:
            ErrorCode() :
                Header(Id::ErrorCode, 4)
            {}

        private:
            uint32_t : 21; // reserved
            uint32_t m_Class : 3; /* [3 ~ 6] */
            uint32_t m_Number: 8; /* [0 ~ 99]*/
            uint8_t  m_Reason[0];
        };

        class UnknownAttributes : public Header {
        public:
            UnknownAttributes():
                Header(Id::UnknownAttributes,0)
            {}

        private:
            uint16_t m_Attrs[0];
        };

        class ReflectedFrom : public MappedAddress {
        public:
            ReflectedFrom() :
                MappedAddress(Id::ReflectedFrom)
            {}
        };

        class Realm : public Header {
        public:
            Realm() :
                Header(Id::Realm, 0)
            {}
        private:
            uint8_t m_Text[0];
        };

        class Nonce : public Header {
        public:
            Nonce():
                Header(Id::Nonce, 0)
            {}

        private:
            uint8_t m_Text[0];
        };

        class XorMappedAddress : public MappedAddress {
        public:
            XorMappedAddress() :
                MappedAddress(Id::XorMappedAddress)
            {}
        };

        class Software : public Header {
        public:
            Software():
                Header(Id::Software, 0)
            {}

        private:
            uint8_t m_Text[0];
        };

        class AlternateServer : public MappedAddress {
        public:
            AlternateServer() :
                MappedAddress(Id::AlternateServer)
            {}
        };

        class Fingerprint : public Header {
        public:
            Fingerprint() :
                Header(Id::Fingerprint, 4)
            {}

        private:
            uint32_t m_CRC32;
        };

        class Priority : public Header {
        public:
            Priority() :
                Header(Id::Priority, 4)
            {}

        private:
            uint32_t m_Pri;
        };

        class UseCandidate : public Header {
        public:
            UseCandidate():
                Header(Id::UseCandidate, 0)
            {}
        };

        class Role : public Header {
        public:
            Role(bool bControlling) :
                Header(bControlling ? Id::IceControlling : Id::IceControlled, 8)
            {}
        private:
            uint64_t m_Tiebreaker;
        };
    }

    namespace PACKET {
        class UDP_HEADER {
        public:
            UDP_HEADER()
            {}

            UDP_HEADER(MsgType eType, const TransId& transId) :
                m_MsgId(boost::asio::detail::socket_ops::host_to_network_short(static_cast<uint16_t>(eType))), m_AttrsLen(0)
            {
                memcpy(m_TransId, transId, sTransationLength);
            }

            MsgType Id() const 
            {
                return static_cast<MsgType>(boost::asio::detail::socket_ops::network_to_host_short(m_MsgId));
            }

            uint16_t HeaderLength() const
            {
                return sStunHeaderLength;
            }

            uint16_t AttrsLen() const
            {
                return m_AttrsLen;
            }

            void AttrsLen(uint16_t length)
            {
                m_AttrsLen = boost::asio::detail::socket_ops::host_to_network_short(length);
            }

        private:
            uint16_t m_MsgId;
            uint16_t m_AttrsLen;
            uint16_t m_TransId[sTransationLength];
        };

        class TCP_HEADER {
        public:
            TCP_HEADER()
            {}

            TCP_HEADER(MsgType eType, const TransId& transId) :
                m_MsgId(boost::asio::detail::socket_ops::host_to_network_short(static_cast<uint16_t>(eType))), m_AttrsLen(0)
            {
                memcpy(m_TransId, transId, sTransationLength);
            }

            MsgType Id() const
            {
                return static_cast<MsgType>(m_MsgId);
            }

            //uint16_t HeaderLength() const
            //{
            //    return sStunHeaderLength + 20;
            //}

            uint16_t AttrsLen() const
            {
                return m_AttrsLen;
            }

            void AttrsLen(uint16_t length)
            {
                m_AttrsLen = boost::asio::detail::socket_ops::host_to_network_short(length);
                m_Framing  = boost::asio::detail::socket_ops::host_to_network_short(length + sStunHeaderLength);
            }

        private:
            uint16_t m_Framing;
            uint16_t m_MsgId;
            uint16_t m_AttrsLen;
            uint16_t m_TransId[sTransationLength];
        };

        template<class packet_header, MTU mtu>
        class StunPacket : public packet_header {
        public:
            StunPacket()
            {
            }

            StunPacket(MsgType eType, const TransId& transId) :
                packet_header(eType, transId)
            {
            }
        public:
            uint8_t* Attributes()
            {
                return m_Attrs;
            }

            uint8_t* Data()
            {
                return reinterpret_cast<uint8_t*>(this);
            }

            uint16_t Size() const
            {
                return sizeof(*this);
            }

        private:
            uint8_t m_Attrs[mtu];
        };
    }
}

#if 0
namespace STUN {

    static const uint32_t sMagicCookie  = boost::asio::detail::socket_ops::host_to_network_long(0x2112A442);
    static const int sIPv4PathMTU       = 548;
    static const int sIPv6PathMTU       = 1280;
    static const int sTransationLen     = 16;

    enum class AgentRole : uint8_t {
        Controlling = 0,
        Controlled = 1,
    };

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
            MappedAddress   = 0x0001,
            RespAddress     = 0x0002,
            ChangeReq       = 0x0003,
            SourceAddress   = 0x0004,
            ChangedAddress  = 0x0005,
            Username        = 0x0006,
            Password        = 0x0007,

            MessageIntegrity = 0x0008,
            ErrorCode        = 0x0009,

            UnknownAttributes = 0x000A,
            ReflectedFrom     = 0x000B,

            Realm = 0x0014,
            Nonce = 0x0015,

            XorMappedAddress = 0x0020,

            Priority        = 0x0024, /* RFC8445 16.1 */
            UseCandidate    = 0x0025, /* RFC8445 16.1 */
            IceControlled   = 0x8029, /* RFC8445 16.1 */
            IceControlling  = 0x802A, /* RFC8445 16.1 */

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

        struct Priority : stun_attr_header {
            Priority() : stun_attr_header(Identifier::Priority) { _length = 4; /* 32 bit */ }
            Priority(uint32_t priority) : stun_attr_header(Identifier::Priority), _value(priority) { _length = 4; }

            uint32_t _value;
        };

        struct UseCandidate : stun_attr_header {
            UseCandidate() : stun_attr_header(Identifier::UseCandidate) {}
        };

        struct IceControlled : stun_attr_header {
            IceControlled() : stun_attr_header(Identifier::IceControlled) {}
        };

        struct IceControlling : stun_attr_header {
            IceControlling() : stun_attr_header(Identifier::IceControlling) {}
        };

        /* 
         * <RFC8445 16.1>
         * The content of the ICE-CONTROLLED(or ICE-CONTROLLING) is a 64-bit unsigned
         * Integer in network byte order, which contains a random number
         */
        struct IceRoleAttr : stun_attr_header {
            IceRoleAttr(bool bControlling) : 
                stun_attr_header(bControlling ? Identifier::IceControlling : Identifier::IceControlled){
                _length = 8;
            }
            uint64_t _value;
        };
    }

    namespace PACKET{
        struct udp_stun_packet_header {
            udp_stun_packet_header() :
                _length(0)
            {
            }
            uint16_t HeaderLength() const { return sizeof(udp_stun_packet_header); }
            uint16_t PacketLength() const { return _length; }
            void PacketLength(uint16_t len) { _length = len; }

            uint8_t* Data() { return reinterpret_cast<uint8_t*>(this); }
            const uint8_t* Data() const { return reinterpret_cast<const uint8_t*>(this); }

            void MsgIdentifier(uint16_t id) { _id = id; }
            uint16_t _id;
            uint16_t _length;
            uint8_t  _transation[16];
        };

        struct tcp_stun_packet_header {
            tcp_stun_packet_header() :
                _length(0)
            {
            }

            uint16_t HeaderLength() const   { return sizeof(tcp_stun_packet_header); }
            uint16_t PacketLength() const   { return _length; }
            void PacketLength(uint16_t len) { _length = len; }

            uint8_t* Data() { return reinterpret_cast<uint8_t*>(this); }
            const uint8_t* Data() const { return reinterpret_cast<const uint8_t*>(this); }

            void MsgIdentifier(uint16_t id) { _id = id; }

            uint16_t _framing;
            uint16_t _id;
            uint16_t _length;
            uint8_t  _transation[16];
        };

        struct udp_stun_packet : public udp_stun_packet_header {
            uint8_t _attr[sIPv6PathMTU];
        };

        struct tcp_stun_packet : public tcp_stun_packet_header {
            uint8_t _attr[sIPv6PathMTU];
        };

        using stun_packet = udp_stun_packet;
    }
}
#endif