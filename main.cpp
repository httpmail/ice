
#include <stdint.h>
#include <iostream>
#include "stunmsg.h"
#include "channel.h"
#include "agent.h"
#include "stream.h"

int main() 
{
    ICE::CAgent agent;

    ICE::Stream stream(1, ICE::Stream::Pipline::udp, "192.168.110.232");

    stream.Create(agent.AgentConfig());


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
    return 1;
}
