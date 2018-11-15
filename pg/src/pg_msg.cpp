#include "pg_msg.h"
#include "pg_log.h"
#include "pg_listener.h"

#include <assert.h>
#include <memory>

namespace PG {

    MsgEntity::MsgEntityContainer MsgEntity::m_msg_entities;

    MsgEntity::MsgEntity()
    {
        assert(m_msg_entities.find(this) != m_msg_entities.end());
        m_msg_entities.insert(this);
        m_thread = std::thread(MsgDispitcherThread, this);
    }

    MsgEntity::~MsgEntity()
    {
        Close();
    }

    void MsgEntity::Close()
    {
        std::lock_guard<std::mutex> locker(m_queue_mutex);
        if (!m_quit)
        {
            m_quit = true;

            if (m_thread.joinable())
                m_thread.join();
        }
    }

    bool MsgEntity::SendMessage(MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        OnMsgReceived(msgId, wParam, lParam);
        return true;
    }

    bool MsgEntity::PostMessage(MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        std::lock_guard<std::mutex> locker(m_queue_mutex);
        CMsgWrapper msg(msgId, wParam, lParam);
        m_msg_queue.push_back(msg);
        m_queue_condition.notify_one();
        return true;
    }

    bool MsgEntity::RegisterEventListener(MSG_ID msgId, CListener * listener)
    {
        return RegisterListener(msgId, listener);
    }

    bool MsgEntity::UnregisterEventListenner(MSG_ID msgId, CListener * listener)
    {

        return UnregisterListener(msgId, listener);
    }

    bool MsgEntity::RegisterListener(MSG_ID msgId, CListener * listener)
    {
        std::lock_guard<std::mutex> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor == m_listeners.end())
        {
            LOG_ERROR("MSG", "RegisterListener : nonexistence Message[id :%d]", msgId);
            return false;
        }
        else
        {
            auto listener_container = itor->second;
            assert(listener_container);
            listener_container->insert(listener);
            return true;
        }
    }

    bool MsgEntity::UnregisterListener(MSG_ID msgId, CListener * listener)
    {
        std::lock_guard<std::mutex> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor == m_listeners.end())
        {
            LOG_ERROR("MSG", "UnregisterListener : nonexistence Message[id :%d]", msgId);
            return false;
        }
        else
        {
            auto listener_container = itor->second;
            assert(listener_container);
            listener_container->erase(listener);
            return true;
        }
    }

    bool MsgEntity::RegisterEvent(MSG_ID msgId)
    {
        std::lock_guard<std::mutex> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor != m_listeners.end())
            return true;
        try
        {
            std::auto_ptr<ListenerContainer> listenerContainer(new ListenerContainer);
            if (listenerContainer.get())
            {
                m_listeners[msgId] = listenerContainer.release();
                return true;
            }
            return false;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("MSG", "RegisterEvent exception :%s", e.what());
            return false;
        }
    }

    void MsgEntity::NotifySubscriber(MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        auto itor = m_listeners.find(msgId);
        if (itor != m_listeners.end())
        {
            for (auto subscriber : *itor->second)
            {
                subscriber->OnEventFired(msgId);
            }
        }
    }

    void MsgEntity::MsgDispitcherThread(MsgEntity * pOwn)
    {
        assert(pOwn);

        while (1)
        {
            std::unique_lock<std::mutex> locker(pOwn->m_queue_mutex);
            pOwn->m_queue_condition.wait(locker, [&pOwn] {
                return !pOwn->m_msg_queue.empty() || pOwn->m_quit;
            });

            if (pOwn->m_quit)
                break;

            MsgQueue tempQueue(pOwn->m_msg_queue);
            pOwn->m_msg_entities.clear();
            locker.unlock();

            for (auto msg : tempQueue)
            {
                pOwn->OnMsgReceived(msg.MsgId(), msg.WParam(), msg.LParam());
                {
                    std::lock_guard<std::mutex> locker(pOwn->m_queue_mutex);
                    if (pOwn->m_quit)
                        break;
                }
            }
        }
    }
}
