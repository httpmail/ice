#include "stunmsg.h"

namespace STUN {

    bool Message::AddAttribute(const ATTR::MappedAddressAttr  &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::RespAddressAttr    &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::ChangedAddressAttr &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::ReflectedFromAttr  &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::SourceAddressAttr  &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::ChangeRequestAttr  &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::ErrorCodeAttr &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::UnknownAttributes &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::XorMappedAddressAttr &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::Software &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::Realm &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::Nonce &attr)
    {
        return true;
    }

    bool Message::AddAttribute(const ATTR::AlternateServer &attr)
    {
        return true;
    }
}

