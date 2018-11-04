
#include "pg_util.h"
#include "stunmsg.h"
#include "channel.h"
#include "stunprotocol.h"

int main() {
    ICE::UDPChannel channel;

    STUN::TransId s;
    STUN::BindingRequestMsg<STUN::PACKET::UDP_HEADER, STUN::PROTOCOL::RFC5389> bingMsg(1,s);

    if (!channel.Bind("10.216.17.182", 32000))
        return false;


    int a;
    auto _1 = boost::asio::buffer(&a, sizeof(a));
    auto _2 = boost::asio::buffer(&a, sizeof(a));

    std::vector<boost::asio::mutable_buffer> v;
    v.push_back(_1);
    v.push_back(_2);
    if (!channel.BindRemote("10.216.17.216", 3478))
        return false;

//    bingMsg.Finalize();

    channel.Write(bingMsg.GetData(), bingMsg.GetLength());

    uint8_t buf[1024];
    int a = channel.Read(buf, sizeof(buf));

    return 1;
}
