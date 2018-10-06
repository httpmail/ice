#pragma once

#include <map>
#include <vector>
#include <condition_variable>
#include <mutex>
#include "pg_object.h"

namespace PG{
    class MsgEntity : CObject {
    public:
        using MSG_ID = uint16_t;
        using WPARAM = void*;
        using LPARAM = void*;

    public:
        MsgEntity(const std::string& unique_name);
        virtual ~MsgEntity();

    public:
        void Close();

    public:
        static bool SendMessage(const std::string& receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam);
        static bool PostMessage(const std::string& receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam);

    private:
        class CMsgWrapper {
        public:
            CMsgWrapper(MSG_ID msgId, WPARAM wParam, LPARAM lParam) :
                m_msg_id(msgId), m_wparam(wParam), m_lparam(lParam)
            {
            }
            virtual ~CMsgWrapper() {}

            MSG_ID MsgId()  const { return m_msg_id; }
            WPARAM WParam() const { return m_wparam; }
            LPARAM LParam() const { return m_lparam; }

        private:
            MSG_ID m_msg_id;
            WPARAM m_wparam;
            LPARAM m_lparam;
        };
        using MsgEntityContainer = std::map<std::string, MsgEntity*>;
        using MsgQueue           = std::vector<CMsgWrapper>;

    protected:
        virtual void OnMsgReceived(MSG_ID msgId, WPARAM wParam, LPARAM lParam) = 0 {};

    protected:
        static void MsgDispitcherThread(MsgEntity *pOwn);

    private:
        MsgQueue                m_msg_queue;
        std::condition_variable m_queue_condition;
        std::mutex              m_queue_mutex;
        std::thread             m_thread;
        bool                    m_quit;

    private:
        static MsgEntityContainer m_msg_entities;
    };
}