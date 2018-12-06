
#include <stdint.h>
#include <iostream>
#include "stunmsg.h"
#include "channel.h"
#include "agent.h"
#include "stream.h"
#include <thread>
#include "pg_buffer.h"
#include "pg_log.h"

#include <string>
#include <atomic>
#include <iostream>

PG::FIFOBuffer<std::string, 10> Buffer;

PG::CircularBuffer<char, 128, 1> CharBuffer;

class A1 {
public:
    A1()
    {
        std::cout << "A1()" << std::endl;
    }

    ~A1()
    {
        std::cout << "~A1()" << std::endl;
    }
};

std::vector < std::shared_ptr<A1> > A1V;
std::mutex mutex;
std::condition_variable cond;

void WriteThread(int i)
{
    std::unique_lock<std::mutex> locker(mutex);
    auto ret = cond.wait_for(locker, std::chrono::seconds(1000));
    std::cout << "Print" << (ret == std::_Cv_status::no_timeout) << std::endl;
}

void ReaderThread()
{
    std::this_thread::get_id();
}

int *x = new int;
void Get(const int*& p)
{
    std::cout << x << std::endl;
    *x = 1;
    p = x;
}

int main() 
{

    const int *p = nullptr;
    Get(p);

    p = nullptr;

    std::cout << x << std::endl;

#if 0
    ICE::CAgent agent;
    ICE::CAgentConfig config;

    config.AddStunServer("216.93.246.118");

    ICE::Stream stream(1, ICE::Stream::Pipline::udp, "192.168.110.232");
    stream.Create(config);
    while (1);
#endif
#if 0
    ICE::UDPChannel channel;

    channel.Bind("192.168.110.229", 12345);
    channel.BindRemote("216.93.246.18", 3478);

    STUN::TransId s;
    STUN::MessagePacket::GenerateRFC3489TransationId(s);
    STUN::SharedSecretReqMsg msg(s);

    STUN::PACKET::stun_packet recv_packet;
    channel.Write(msg.GetData(), msg.GetLength());
    channel.Read(&recv_packet, sizeof(recv_packet));

    auto recv = recv_packet;
    STUN::MessagePacket p1(recv_packet);
#endif
    //std::this_thread::sleep_for(std::chrono::seconds(16));
    return 1;
}
