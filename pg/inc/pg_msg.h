#pragma once

#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <condition_variable>
#include <mutex>
#include "pg_object.h"

namespace PG{
    class CListener;

    class MsgEntity {
    public:
        using MSG_ID = uint16_t;
        using WPARAM = void*;
        using LPARAM = void*;

    public:
        MsgEntity();
        MsgEntity(const MsgEntity&) = delete;
        virtual ~MsgEntity();

    public:
        void Close();

    public:
        bool SendMessage(MSG_ID msgId, WPARAM wParam, LPARAM lParam);
        bool PostMessage(MSG_ID msgId, WPARAM wParam, LPARAM lParam);
        bool RegisterEventListener(MSG_ID msgId, CListener *listener);
        bool UnregisterEventListenner(MSG_ID msgId, CListener *listener);

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

    protected:
        virtual void OnMsgReceived(MSG_ID msgId, WPARAM wParam, LPARAM lParam) = 0 {};

        bool RegisterListener(MSG_ID msgId, CListener *listener);
        bool UnregisterListener(MSG_ID msgId, CListener *listener);
        bool RegisterEvent(MSG_ID msgId);
        void NotifySubscriber(MSG_ID msgId, WPARAM wParam, LPARAM lParam);

    protected:
        static void MsgDispitcherThread(MsgEntity *pOwn);

    private:
        using MsgEntityContainer = std::unordered_set<MsgEntity*>;
        using MsgQueue           = std::vector<CMsgWrapper>;
        using ListenerContainer  = std::set<CListener*>;
        using EventLisennerVes   = std::unordered_map<MSG_ID, ListenerContainer*>;

    private:
        EventLisennerVes        m_listeners;
        std::mutex              m_listeners_mutex;

        MsgQueue                m_msg_queue;
        std::condition_variable m_queue_condition;
        std::mutex              m_queue_mutex;
        std::thread             m_thread;
        bool                    m_quit;

    private:
        static MsgEntityContainer m_msg_entities;
    };
}