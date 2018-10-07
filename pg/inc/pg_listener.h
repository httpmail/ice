#pragma once

#include "pg_msg.h"

namespace PG {
    class CListener {
    public:
        CListener() {}
        virtual ~CListener() {}

    public:
        virtual void OnEventFired(MsgEntity::MSG_ID msg_id) = 0 {}
    };
}