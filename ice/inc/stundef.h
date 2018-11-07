#pragma once

#include <stdint.h>
#include <boost/asio.hpp>

#include "pg_util.h"

#pragma warning (disable:4200)
#pragma pack(4)

using namespace boost::asio::detail::socket_ops;

namespace STUN {
    static const uint32_t sMagicCookie = 0x2112A442;
    static const uint16_t sIPv4PathMTU = 548;
    static const uint16_t sIPv6PathMTU = 1280;
    static const uint16_t sTransationLength = 16;
    static const uint16_t sStunHeaderLength = 20;
    static const uint16_t sStunPacketLength = sIPv4PathMTU; /* NOTICE just set stun packet length as the MTU of ipv4*/

    using TransId = uint8_t[sTransationLength];
    using TransIdRef = uint8_t(*)[sTransationLength];
    using TransIdConstRef = const uint8_t(*)[sTransationLength];

    using Attrbutes         = uint8_t[sStunPacketLength];
    using AttrbutesRef      = uint8_t(*)[sStunPacketLength];
    using AttrbutesConstRef = const uint8_t(*)[sStunPacketLength];

    enum class AgentRole : uint8_t {
        Controlling = 0,
        Controlled = 1
    };

    enum class ErrorCode : uint16_t {
        BadRequest = 404,
        Unauthorized = 401,
        UnknownAttribute = 420,
        StaleCredentials = 430,
        IntegrityCheckFailure = 431,
        MissingUsername = 432,
        UseTLS = 433,
        ServerError = 500,
        GlobalFailure = 600,
    };

    enum class MsgType : uint16_t {
        BindingRequest = 0x0001,
        BindingResp = 0x0101,
        BindingErrResp = 0x0111,
        SSRequest = 0x0002,
        SSResponse = 0x0102,
        SSErrResp = 0x1102,
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
            MappedAddress = 0x0001,
            RespAddress = 0x0002,
            ChangeRequest = 0x0003,
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
            Priority = 0x0024, /* RFC8445 16.1 */
            UseCandidate = 0x0025, /* RFC8445 16.1 */
            Fingerprint = 0x8028,
            IceControlled = 0x8029, /* RFC8445 16.1 */
            IceControlling = 0x802A, /* RFC8445 16.1 */
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
                m_type(host_to_network_short(static_cast<uint16_t>(type))), m_length(host_to_network_short(length))
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
                return static_cast<Id>(m_type);
            }

        protected:
            uint16_t m_type;
            uint16_t m_length;
        };

        /*
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |0 0 0 0 0 0 0 0|    Family     |           Port                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        |                 Address (32 bits or 128 bits)                 |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */
        class MappedAddress : public Header {
        public:
            MappedAddress(Id id = Id::MappedAddress) :
                Header(id, 8)
            {}

            int16_t Port() const
            {
                return m_Port;
            }

            void Port(int16_t port)
            {
                m_Port = port;
            }

            uint32_t Address() const
            {
                return m_Address;
            }

            void Address(uint32_t address)
            {
                m_Address = address;
            }

            AddressFamily Family() const
            {
                return  static_cast<AddressFamily>(m_Family);
            }
        private:
            uint8_t : 8; // reserved
                      uint8_t   m_Family : 8; // family
                      uint16_t  m_Port : 16;// port
                      uint32_t  m_Address : 32;
        };

        class ResponseAddress : public MappedAddress {
        public:
            ResponseAddress() :
                MappedAddress(Id::RespAddress)
            {}
        };

        /*
            The CHANGE-REQUEST attribute is used by the client to request that
            the server use a different address and/or port when sending the
            response.  The attribute is 32 bits long, although only two bits (A
            and B) are used:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            The meaning of the flags is:

            A: This is the "change IP" flag.  If true, it requests the server
            to send the Binding Response with a different IP address than the
            one the Binding Request was received on.

            B: This is the "change port" flag.  If true, it requests the
            server to send the Binding Response with a different port than the
            one the Binding Request was received on.
         */
        class ChangeRequest : public Header {
        private:
            uint8_t : 1;
                      uint8_t m_ChangePort : 1;
                      uint8_t m_ChangeIP : 1;
                      uint32_t : 29;

        public:
            ChangeRequest(bool changeIP) :
                Header(Id::ChangeRequest, 4)
            {}
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

        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Reserved, should be 0         |Class|     Number    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Reason Phrase (variable)                                ..
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        class ErrorCode : public Header {
        private:
            union
            {
                struct {
                    uint32_t m_Number : 8; /* [0 ~ 99]*/
                    uint32_t m_Class : 3;  /* [3 ~ 6] */
                    uint32_t : 21;
                }details;
                uint32_t content;
            };
            uint8_t  m_Reason[0];

        public:
            ErrorCode() :
                Header(Id::ErrorCode, 4), content(0)
            {}

            uint32_t Value() const
            {
                return this->content;
            }

            uint32_t Class() const
            {
                return details.m_Class;
            }

            void Class(uint8_t classCode)
            {
                assert(classCode >= 3 && classCode <= 6);
                details.m_Class = classCode;
            }

            uint32_t Number() const
            {
                return details.m_Number;
            }

            void Number(uint8_t number)
            {
                assert(number >= 0 && number <= 99);
                details.m_Number = number;
            }
        };

        class UnknownAttributes : public Header {
        public:
            UnknownAttributes() :
                Header(Id::UnknownAttributes, 0)
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
            Nonce() :
                Header(Id::Nonce, 0)
            {}

        private:
            uint8_t m_Text[0];
        };

        class XorMappedAddress : public Header {
        public:
            XorMappedAddress() :
                Header(Id::XorMappedAddress, 4)
            {}

            int16_t Port() const
            {
                return static_cast<int16_t>((sMagicCookie >> 16) ^ PG::network_to_host(m_Port));
            }

            void Port(int16_t port)
            {
                m_Port = PG::host_to_network(port ^ (sMagicCookie >> 16));
            }

            uint32_t Address() const
            {
                return static_cast<int32_t>(sMagicCookie ^ PG::network_to_host(m_Address));
            }

            void Address(uint32_t address)
            {
                m_Address = PG::host_to_network(address ^ sMagicCookie);
            }

            AddressFamily Family() const
            {
                return  static_cast<AddressFamily>(m_Family);
            }

            uint8_t : 8; // reserved
                      uint8_t     m_Family : 8; // family
                      uint16_t    m_Port : 16;// port
                      uint32_t    m_Address : 32;
        };

        class Software : public Header {
        public:
            Software() :
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

            uint32_t Pri() const
            {
                return m_Pri;
            }
            void Pri(uint32_t pri)
            {
                m_Pri = pri;
            }

        private:
            uint32_t m_Pri;
        };

        class UseCandidate : public Header {
        public:
            UseCandidate() :
                Header(Id::UseCandidate, 0)
            {}
        };

        class Role : public Header {
        public:
            Role(bool bControlling) :
                Header(bControlling ? Id::IceControlling : Id::IceControlled, 8)
            {}

            uint64_t TieBreaker() const
            {
                return m_Tiebreaker;
            }

            void TieBreaker(uint64_t tieBreaker)
            {
                m_Tiebreaker = tieBreaker;
            }

        private:
            uint64_t m_Tiebreaker;
        };
    }

    namespace PACKET1 {
        struct stun_packet {
            uint16_t _msgId;
            uint16_t _length;
            TransId  _transId;
            
        };
    }
    namespace PACKET {
        class StunHeader {
        public:
            StunHeader()
            {}

            StunHeader(MsgType eType, const TransId& transId) :
                m_MsgId(boost::asio::detail::socket_ops::host_to_network_short(static_cast<uint16_t>(eType))), m_AttrsLen(0)
            {
                static_assert(sizeof(transId) == sTransationLength, "transation id length MUST be 16");
                memcpy(m_TransId, transId, sTransationLength);
            }

            MsgType Type() const 
            {
                return static_cast<MsgType>(m_MsgId);
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
                m_AttrsLen = length;
            }

            auto GetTransId() const -> TransIdConstRef
            {
                return &m_TransId;
            }

            auto GetTransId() ->TransIdRef
            {
                return &m_TransId;
            }


        private:
            uint16_t m_MsgId;
            uint16_t m_AttrsLen;
            TransId  m_TransId;
        };

        class StunPacket : public StunHeader {
        public:
            StunPacket()
            {
            }

            StunPacket(MsgType eType, const TransId& transId) :
                StunHeader(eType, transId)
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

            const uint8_t* Data() const
            {
                return reinterpret_cast<const uint8_t*>(this);
            }

            uint16_t Size() const
            {
                return sizeof(*this);
            }
        private:
            uint8_t m_Attrs[sStunPacketLength];
        };
    }
}