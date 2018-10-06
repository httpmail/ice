#include "pg_msg.h"
#include "pg_log.h"

#include <assert.h>
#include <memory>
#include "..\inc\pg_msg.h"

namespace PG {

    MsgEntity::MsgEntityContainer MsgEntity::m_msg_entities;

    MsgEntity::MsgEntity(const std::string& unique_name) :
        CObject(unique_name)
    {
        assert(m_msg_entities.find(unique_name) != m_msg_entities.end());
        m_msg_entities[unique_name] = this;
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

        std::lock_guard<std::mutex> locker(pEntity->m_queue_mutex);
        CMsgWrapper msg(msgId, wParam, lParam);
        pEntity->m_msg_queue.push_back(msg);
        pEntity->m_queue_condition.notify_one();

        return true;
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