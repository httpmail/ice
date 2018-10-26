#include "pg_msg.h"
#include "pg_log.h"
#include "pg_listener.h"

#include <assert.h>
#include <memory>

#if 0
namespace PG {

    MsgEntity::MsgEntityContainer MsgEntity::m_msg_entities;

    MsgEntity::MsgEntity()
    {
        assert(m_msg_entities.find(this) != m_msg_entities.end());
        m_msg_entities.insert(this)
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

    bool MsgEntity::SendMessage(const std::string & receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        auto itor = m_msg_entities.find(receiver);
        if (itor == m_msg_entities.end())
        {
            LOG_ERROR("MSG", "SendMessage :[target %s] unregistered", receiver.c_str());
            return false;
        }

        assert(itor->second);

        itor->second->OnMsgReceived(msgId, wParam, lParam);
        return true;
    }

    bool MsgEntity::PostMessage(const std::string & receiver, MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        auto itor = m_msg_entities.find(receiver);
        if (itor == m_msg_entities.end())
        {
            LOG_ERROR("MSG", "SendMessage :[target %s] unregistered", receiver.c_str());
            return false;
        }

        auto pEntity = itor->second;

        assert(pEntity);

        std::lock_guard<std::mutex> locker(pEntity->m_queue_mutex);
        CMsgWrapper msg(msgId, wParam, lParam);
        pEntity->m_msg_queue.push_back(msg);
        pEntity->m_queue_condition.notify_one();

        return true;
    }

    bool MsgEntity::RegisterEventListener(const std::string & msg_entity, MSG_ID msgId, CListener * listener)
    {
        assert(listener);

        auto itor = m_msg_entities.find(msg_entity);
        if (itor == m_msg_entities.end())
        {
            LOG_ERROR("MSG", "RegisterEventListener :[target %s] unregistered", msg_entity.c_str());
            return false;
        }

        auto pEntity = itor->second;

        assert(pEntity);

        return pEntity->RegisterListener(msgId, listener);
    }

    bool MsgEntity::UnregisterEventListenner(const std::string & msg_entity, MSG_ID msgId, CListener * listener)
    {
        assert(listener);

        auto itor = m_msg_entities.find(msg_entity);
        if (itor == m_msg_entities.end())
        {
            LOG_ERROR("MSG", "UnregisterEventListenner :[target %s]", msg_entity.c_str());
            return false;
        }

        auto pEntity = itor->second;

        assert(pEntity);

        return pEntity->UnregisterListener(msgId, listener);
    }

    bool MsgEntity::RegisterListener(MSG_ID msgId, CListener * listener)
    {
        std::lock_guard<std::mutex> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor == m_listeners.end())
        {
            LOG_ERROR("MSG", "RegisterListener :[target %s, msg_id %d] no such message", m_unique_name.c_str(), msgId);
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
            LOG_ERROR("MSG", "RegisterListener :[target %s, msg_id %d] no such message", m_unique_name.c_str(), msgId);
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
#endif
