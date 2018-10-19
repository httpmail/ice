#pragma once

#include "stundef.h"
#include <assert.h>
#if 0
class MessagePacket {
public:
    MessagePacket() {}
    virtual ~MessagePacket() = 0 {}

    virtual const uint8_t* Data()   const = 0;
    virtual uint16_t       Length() const = 0;

    virtual uint16_t EncodeAttribute(const ATTR::MappedAddressAttr  &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::RespAddressAttr    &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::ChangedAddressAttr &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::ReflectedFromAttr  &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::SourceAddressAttr  &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::ChangeRequestAttr  &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::ErrorCodeAttr &attr) = 0;
    virtual uint16_t EncodeAttribute(const ATTR::UnknownAttributes &attr) = 0;
    //virtual uint16_t EncodeAttribute(const ATTR::XorMappedAddressAttr &attr) = 0;
    //virtual uint16_t EncodeAttribute(const ATTR::Software &attr) = 0;
    //virtual uint16_t EncodeAttribute(const ATTR::Realm &attr) = 0;
    //virtual uint16_t EncodeAttribute(const ATTR::Nonce &attr) = 0;
    //virtual uint16_t EncodeAttribute(const ATTR::AlternateServer &attr) = 0;
};

template<class packet_type, class protocol_impl>
class MessagePacketImpl : public MessagePacket {
public:
    MessagePacketImpl() :
        m_attr_pointer(m_packet._attr)
    {
        assert(m_attr_pointer);
    }

    virtual ~MessagePacketImpl() {}

    virtual const uint8_t* Data() const override final
    {
        return reinterpret_cast<const uint8_t*>(&m_packet);
    }

    virtual uint16_t Length() const override final
    {
        return m_packet._length + m_packet.HeaderLength();
    }

    uint16_t EncodeAttribute(const ATTR::MappedAddressAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::RespAddressAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::ChangedAddressAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::ReflectedFromAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::SourceAddressAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::ChangeRequestAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::ErrorCodeAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::UnknownAttributes &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::XorMappedAddressAttr &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }
#if 0
    uint16_t EncodeAttribute(const ATTR::Software &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::Realm &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

    uint16_t EncodeAttribute(const ATTR::Nonce &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }
#endif
    uint16_t EncodeAttribute(const ATTR::AlternateServer &attr)
    {
        return m_packet._length += protocol_impl::EncodeAttribute(attr, m_attr_pointer + m_packet._length);
    }

private:
    packet_type m_packet;
    uint8_t    *m_attr_pointer;
};

class Message {
public:
    Message(MessagePacket *packet) : m_packet(packet)
    {
        assert(m_packet);
    }

    virtual ~Message() = 0 {}

public:
    const uint8_t* Data() const { assert(m_packet); return m_packet->Data(); }
    uint16_t     Length() const { assert(m_packet); return m_packet->Length(); }

public:
    bool AddAttribute(const ATTR::MappedAddressAttr  &attr);
    bool AddAttribute(const ATTR::RespAddressAttr    &attr);
    bool AddAttribute(const ATTR::ChangedAddressAttr &attr);
    bool AddAttribute(const ATTR::ReflectedFromAttr  &attr);
    bool AddAttribute(const ATTR::SourceAddressAttr  &attr);
    bool AddAttribute(const ATTR::ChangeRequestAttr  &attr);
    bool AddAttribute(const ATTR::ErrorCodeAttr &attr);
    bool AddAttribute(const ATTR::UnknownAttributes &attr);
    bool AddAttribute(const ATTR::XorMappedAddressAttr &attr);
    bool AddAttribute(const ATTR::Software &attr);
    bool AddAttribute(const ATTR::Realm &attr);
    bool AddAttribute(const ATTR::Nonce &attr);
    bool AddAttribute(const ATTR::AlternateServer &attr);
    virtual bool Finalize() = 0;

private:
    MessagePacket *m_packet;
};

class BindRequestMsg : public Message {
public:
    template < typename packet_type, typename protocol_impl, template<typename, typename> class packet_impl = MessagePacketImpl>
    BindRequestMsg(packet_impl<packet_type, protocol_impl> *impl) :
        Message(impl)
    {
    }

    virtual ~BindRequestMsg()
    {
    }

    virtual bool Finalize() { return true; }
};
#endif
namespace STUN{
    template<class packet_type>
    class MessagePacket {
    public:
        MessagePacket();
        virtual ~MessagePacket() = 0 {}

        const uint8_t* Data()   const { return reinterpret_cast<const uint8_t*>(&m_packet); }
        uint16_t       Length() const { return m_packet._length + m_packet.HeaderLength(); }

    protected:
        packet_type m_packet;
    };

    template<class packet_type, class protocol_version>
    class BindRequestMessage : public MessagePacket<packet_type> {
    public:
        BindMessage();
        virtual ~BindMessage();
    };

    template<class packet_type, class protocol_version>
    class BindRespMessage : public MessagePacket<packet_type> {
    public:
        BindRespMessage();
        virtual ~BindRespMessage();
    };
}
