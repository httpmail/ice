
#include "pg_log.h"
#include "channel.h"
#include <thread>

class Server {
public:
    Server()
    {
    }

    ~Server()
    {
        if (m_AcceptThread.joinable())
            m_AcceptThread.join();

        if (m_ReceiveThread.joinable())
            m_ReceiveThread.join();
    }

private:
    static void AcceptThread(Server* pInstance)
    {
    }

    static void ReceiveThread(Server* pInstance)
    {
    }

private:
    std::thread m_AcceptThread;
    std::thread m_ReceiveThread;
    ICE::CTCPChannel m_channel;
};


int main(void)
{
    PG::log::Instance().Initlize();
    LOG_INFO("testing",  "123");
    LOG_INFO("testing2", "321");

    ICE::CTCPChannel tcp;
    return 0;
}