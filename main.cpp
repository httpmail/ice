
#include "pg_util.h"
#include "stunmsg.h"
#include "channel.h"
#include "stunprotocol.h"

int main() {
    ICE::UDPChannel channel;

    STUN::BindingRequestMsg<STUN::PACKET::udp_stun_packet, STUN::PROTOCOL::RFC5389> bingMsg(1);

    if (!channel.Bind("10.216.17.182", 32000))
        return false;

    if (!channel.BindRemote("10.216.17.216", 3478))
        return false;
    
    STUN::ATTR::IceRoleAttr role(true);
    bingMsg.AddAttribute<STUN::PROTOCOL::RFC5389>(role);

    bingMsg.Finalize();

    channel.Write(bingMsg.GetData(), bingMsg.GetLength());

    uint8_t buf[1024];
    int a = channel.Read(buf, sizeof(buf));

    return 1;
}
