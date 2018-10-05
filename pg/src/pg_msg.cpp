#include "pg_msg.h"
#include "pg_log.h"

#include <assert.h>

namespace PG {

    MSG::MsgNameMap MSG::sMsgNameMap;
    MSG::MsgObjMap  MSG::sMsgObjMap;

    MSG::MSG(const std::string& unique_name) :
        CObject(unique_name)
    {
        if (sOjbects.find(unique_name) != sOjbects.end())
        {
            assert(sMsgNameMap.find(unique_name) != sMsgNameMap.end() &&
                sMsgObjMap.find(this) != sMsgObjMap.end());

            sMsgNameMap[unique_name] = this;
            sMsgObjMap[this] = unique_name;
        }
    }

    bool MSG::send(MSG *receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        auto& itor = sMsgObjMap.find(receiver);
        if (itor == sMsgObjMap.end())
        {
            LOG_ERROR("MSG", "msg::send error [sender: %s, receiver : %s]", UniqueStringName().c_str(), receiver->UniqueStringName().c_str());
            return false;
        }

        auto handler = itor->first;
        assert(handler);

        handler->OnMsgReceived(this, msgId, wParam, lParam);
        return true;
    }

    bool MSG::send(const std::string& receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        auto& itor = sMsgNameMap.find(receiver);
        if (itor == sMsgNameMap.end())
        {
            LOG_ERROR("MSG", "msg::send error [sender: %s, receiver : %s]", UniqueStringName().c_str(), receiver.c_str());
            return false;
        }

        auto handler = itor->second;
        assert(handler);

        handler->OnMsgReceived(this,msgId, wParam, lParam);

        return true;
    }

    bool MSG::post(MSG *receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        return true;
    }

    bool MSG::post(const std::string& receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        return true;
    }
}