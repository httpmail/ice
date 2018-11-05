#include "stunprotocol.h"
#include "pg_util.h"

#include <boost/asio.hpp>
#include <assert.h>

using namespace STUN;
using namespace STUN::PROTOCOL;
using namespace boost::asio::detail::socket_ops;

#if 0
namespace Common{
    uint16_t PaddingN(uint8_t * buf, uint16_t length, uint16_t N)
    {
        assert((!(N &(N - 1))) && N); // n MUST be 2^n

        auto padding_size = (length + N - 1) & (~(N-1));
        if (padding_size)
            memset(buf + length, 0, length);
        return length + padding_size;
    }

    uint16_t EncodeAttrHeader(const ATTR::stun_attr_header &hdr, uint8_t *buf)
    {
        assert(buf);

        reinterpret_cast<uint16_t*>(buf)[0] = host_to_network_short(hdr.Id());
        reinterpret_cast<uint16_t*>(buf)[1] = host_to_network_short(hdr.Length());
        return sizeof(hdr);
    }

    uint16_t EncodeAttribute(const ATTR::ErrorCodeAttr &attr, uint8_t *buf)
    {
        assert(buf);

        buf[0] = 0;
        buf[1] = 0;
        buf[2] = attr.detail._class;
        buf[3] = attr.detail._number;
        memcpy(&buf[4], attr._reason, attr.Length() - 4);

        /*
         * The lengths of the reason phrases MUST be a multiple of 4 bytes
         */
        return attr.Length() + PaddingN(&buf[attr.Length()], attr.Length() - 4, 4);
    }
}

uint16_t RFC3489::EncodeAttribute(const ATTR::MappedAddressAttr &attr, uint8_t* buf)
{
    assert(buf);

    buf[0] = 0;
    buf[1] = attr.Family();
    *(reinterpret_cast<uint16_t*>(buf[2])) = host_to_network_short(attr.Port());
    *(reinterpret_cast<uint32_t*>(buf[4])) = host_to_network_long(attr.Address());
    return attr.Length();
}

uint16_t RFC3489::EncodeAttribute(const ATTR::ChangeRequestAttr &attr, uint8_t* buf)
{
    assert(buf);

    *(reinterpret_cast<uint32_t*>(buf)) = host_to_network_long(attr.value());
    return attr.Length();
}

uint16_t RFC3489::EncodeAttribute(const ATTR::ErrorCodeAttr &attr, uint8_t* buf)
{
    assert(buf);
    return Common::EncodeAttribute(attr, buf);
}

uint16_t RFC3489::EncodeAttribute(const ATTR::UnknownAttributes &attr, uint8_t* buf)
{
    assert(buf);

    auto count = attr.Length() / sizeof(attr._first_attr_id[0]);

    for(uint16_t i = 0; i < count; ++i)
    {
        *(reinterpret_cast<uint16_t*>(buf[count << 1])) = host_to_network_short(attr._first_attr_id[i]);
    }

    if (count & 1)
    {
        *(reinterpret_cast<uint16_t*>(buf[attr.Length()])) = host_to_network_short(attr._first_attr_id[count]);
        return attr.Length() + 2;
    }
    else
    {
        return attr.Length();
    }
}

uint16_t RFC3489::EncodeAttribute(const ATTR::UsernameAttr &attr, uint8_t *buf)
{
    return uint16_t();
}

uint16_t RFC3489::EncodeAttribute(const ATTR::MessageIntegrityAttr &attr, uint8_t *buf)
{
    return uint16_t();
}



///////////////////////////////////// RFC5389 /////////////////////////////////////////////////////
uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::UsernameAttr & attr, uint8_t * buf)
{
    assert(buf);

    auto hdr_size = Common::EncodeAttrHeader(attr, buf);
    memcpy(buf + hdr_size, attr._text, attr.Length());

    return attr.Length() + Common::PaddingN(&buf[attr.Length()], attr.Length(), 4);
}

uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::MappedAddressAttr & attr, uint8_t * buf)
{
    return uint16_t();
}

uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::ErrorCodeAttr & attr, uint8_t * buf)
{
    assert(buf);

    buf += Common::EncodeAttrHeader(attr, buf);

    buf[0] = 0;
    buf[1] = 0;
    buf[2] = attr.detail._class;
    buf[3] = attr.detail._number;

    memcpy(&buf[4], attr._reason, attr.Length() - 4);

    return attr.Length() + Common::PaddingN(&buf[attr.Length()], attr.Length(), 4);
}

uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::UnknownAttributes & attr, uint8_t * buf)
{
    assert(buf);

    auto hdr_size = Common::EncodeAttrHeader(attr, buf);

    /* The attribute contains a list of 16-bit values */

    assert(sizeof(attr._first_attr_id[0]) == 2);

    auto attr_num = attr.Length() >> 1;

    uint16_t *attr_list = reinterpret_cast<uint16_t*>(buf);
    for (uint16_t i = 0; i < attr_num; ++i)
        attr_list[i] = host_to_network_short(attr._first_attr_id[i]);

    return attr.Length() + Common::PaddingN(&buf[attr.Length()], attr.Length(), 4);
}

uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::XorMappedAddressAttr & attr, uint8_t * buf)
{
    assert(buf);

    auto header_size = Common::EncodeAttrHeader(attr,buf);

    buf += header_size;

    buf[0] = 0;
    buf[1] = attr.Family();

    *(reinterpret_cast<uint16_t*>(buf[2])) = host_to_network_short(attr.Port() ^ (STUN::sMagicCookie >> 16));
    *(reinterpret_cast<uint32_t*>(buf[4])) = host_to_network_long(attr.Address() ^ STUN::sMagicCookie);

    //TODO ipv6
    return attr.Length();
}

uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::IceRoleAttr & attr, uint8_t * buf)
{
    auto header_size = Common::EncodeAttrHeader(attr, buf);

    buf += header_size;

    reinterpret_cast<uint64_t*>(buf)[0] = 0x12345;
    return attr.Length() + header_size;
}

uint16_t STUN::PROTOCOL::RFC5389::EncodeAttribute(const ATTR::Priority &attr, uint8_t *buf)
{
    auto header_size = Common::EncodeAttrHeader(attr, buf);

    buf += header_size;

    reinterpret_cast<uint32_t*>(buf)[0] = host_to_network_long(attr._value);
    return attr.Length() + header_size;
}

uint16_t STUN::PROTOCOL::RFC5389::Finalize(const Message& message, uint8_t * attr_buf, uint16_t length)
{
    assert(attr_buf && length);

    auto len = AddMessageIntegrityAttribute(&attr_buf[length]);
    len += AddFingerprintAttribute(&attr_buf[length + len]);
    return length + len;
}

void STUN::PROTOCOL::RFC5389::GenerateTransationId(uint8_t* transBuf, int16_t size)
{
    assert(transBuf && size == sTransationLen);

    memcpy(&transBuf[0], &sMagicCookie, sizeof(sMagicCookie));

    auto value = PG::GenerateRandom32();
    memcpy(&transBuf[4], &value, sizeof(value));

    value = PG::GenerateRandom32();
    memcpy(&transBuf[8], &value, sizeof(value));

    value = PG::GenerateRandom32();
    memcpy(&transBuf[12], &value, sizeof(value));
}

uint16_t STUN::PROTOCOL::RFC5389::AddMessageIntegrityAttribute(uint8_t * buf)
{
    ATTR::MessageIntegrityAttr attr;
    return attr.Length();
}

uint16_t STUN::PROTOCOL::RFC5389::AddFingerprintAttribute(uint8_t *buf)
{
    return uint16_t();
}

#endif


namespace STUN{
    namespace PROTOCOL {
    }
}