#pragma once

#include <map>
#include <vector>
#include "pg_object.h"

namespace PG{
    class MSG : public CObject{
    public:
        using WPARAM = void*;
        using LPARAM = void*;
        using MSG_ID = uint16_t;

    public:
        MSG(const std::string& unique_name);
        virtual ~MSG() = 0 {}

    public:
        bool send(MSG *receiver,               MSG_ID msgId, WPARAM wParam, LPARAM lParam);
        bool send(const std::string& receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam);

        bool post(MSG *receiver,               MSG_ID msgId, WPARAM wParam, LPARAM lParam);
        bool post(const std::string& receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam);

    protected:
        virtual void OnMsgReceived(MSG *sender, MSG_ID msgId, WPARAM wParam, LPARAM lParam) = 0 {};

    private:
        class MsgWrapper {
        public:
            MsgWrapper(MSG_ID msgId, WPARAM wParam, LPARAM lParam) :
                m_msg_id(msgId), m_wparam(wParam),m_lparam(lParam)
            {
            }

            MSG_ID  MsgId() const  { return m_msg_id; }
            WPARAM  WParam() const { return m_wparam; }
            LPARAM  LParam() const { return m_lparam; }
        private:
            MSG_ID  m_msg_id;
            WPARAM  m_wparam;
            LPARAM  m_lparam;
        };

    private:
        using MsgNameMap = std::map<std::string, MSG*>;
        using MsgObjMap  = std::map<MSG*, std::string>;
        using MsgQueue = std::vector<MsgWrapper*>;

    private:

    private:
        static MsgNameMap sMsgNameMap;
        static MsgObjMap  sMsgObjMap;
    };
}