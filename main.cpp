
#include <stdint.h>
#include <iostream>
#include "stunmsg.h"
#include "channel.h"

class ABC111 {
public:
    ABC111() 
    {
        std::cout << "ABC111()" << std::endl;
    }

    ~ABC111() {}

    ABC111(int i) 
    {
        std::cout << "ABC111(int i)" << std::endl;
    }
};

class A : public ABC111 {
};

int main() 
{

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
    STUN::MessagePacket p(recv_packet);
    return 1;
}
