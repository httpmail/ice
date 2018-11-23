
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

PG::FIFOBuffer<std::string, 10> Buffer;

PG::CircularBuffer<char, 128, 1> CharBuffer;

void WriteThread(int i)
{

    while (1)
    {
        LOG_INFO("Info","Thread [%d]", i);
        std::this_thread::sleep_for(std::chrono::milliseconds(PG::GenerateRandom(100, 500)));
    }
}

void ReaderThread()
{
    while (1)
    {
        std::cout << "reading... " << std::endl;
        auto& elem = CharBuffer.Lock4Read();
        std::cout << elem.data() << std::endl;
        //CharBuffer.Unlock(elem);
        std::this_thread::sleep_for(std::chrono::milliseconds(PG::GenerateRandom(200,500)));
    }
}

struct A11111 {
    int a;
    int b;
    int c;
    int d;
};

int main() 
{
    PG::CircularBuffer<A11111, 12, 123> I;
    auto& a = I.Lock4Write();
    std::cout << sizeof(a[0]) << std::endl;

    int *a1 = 0;
    decltype(a1) b = a1;

    return 0;
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
