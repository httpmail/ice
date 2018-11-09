
#include <stdint.h>
#include <iostream>
#include <stunprotocol.h>

int main() 
{

    STUN::TransId transId;
    STUN::PROTOCOL::RFC5389::GenerateTransationId(transId);

    int a = 0;
    a++;
#if 0
    ICE::UDPChannel channel;

    channel.Bind("192.168.110.229", 12345);
    channel.BindRemote("216.93.246.18", 3478);

    STUN::TransId s;

    int64_t s1 = 0x0012345678ABCDEF;

    printf("%llx\n", s1);
    printf("%llx\n", PG::host_to_network(s1));

    uint16_t i = 0;
    uint32_t j = 0;
    uint64_t k = 0;
    uint32_t magic = boost::asio::detail::socket_ops::host_to_network_long(STUN::sMagicCookie);
    //memcpy(s, &magic, sizeof(magic));
    STUN::BindingRequestMsg msg(0, s);

    STUN::ATTR::Priority priority;

    msg.AddAttribute<STUN::PROTOCOL::RFC5389>(priority);

    auto aAttr = msg.GetAttributes(STUN::ATTR::Id::AlternateServer);

    channel.Write(msg.GetData(), msg.GetLength());


//    STUN::PACKET::StunPacket packet;
//    channel.Read(packet.Data(),sizeof(packet));
#endif
    return 1;
}
