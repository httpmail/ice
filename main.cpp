
#include <stdint.h>
#include <iostream>
#include "stundef.h"
#include "channel.h"
#include "stunmsg.h"

template<class T>
class root {
public:
    static void AddAttribute()
    {
        T::Add();
    }
};

class child : public root<child> {
public:
    static void Add()
    {
    }
};

using Array = uint8_t[10];

struct A {
public:
    Array m_x;
};

struct ABCX : public A{
public:
};

struct Testing {
    int a;
    int b;
    int c;
};

const Testing* Get()
{
    static int abc[12];
    return (Testing*)(abc);
}

int main() 
{

    child c;
    c.AddAttribute();

    ICE::UDPChannel channel;

    channel.Bind("192.168.110.229", 32000);
    channel.BindRemote("216.93.246.18", 3478);

    STUN::TransId s;

    uint32_t magic = boost::asio::detail::socket_ops::host_to_network_long(STUN::sMagicCookie);
    memcpy(s, &magic, sizeof(magic));
    STUN::BindingRequestMsg msg(0, s);

    channel.Write(msg.GetData(), msg.GetLength());

    uint8_t info[1024];

    STUN::PACKET::StunPacket packet;
    channel.Read(packet.Data(),sizeof(packet));

    auto a = Get();
    delete a;
    return 1;
}
