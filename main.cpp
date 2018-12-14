
#include "agent.h"
#include "stream.h"
#include "session.h"
#include "channel.h"

#include <iostream>
#include <sstream>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>

int main() 
{
#if 0
    ICE::CAgentConfig config;
    ICE::CAgent agent;

    config.AddStunServer("64.235.150.11",3478);
    config.AddStunServer("216.93.246.18", 3478);

    ICE::Session session;

    ICE::Stream audioStream(0, ICE::Stream::Pipline::udp, 0xFFFF, config.DefaultIP(), 3200);
    audioStream.GatheringCandidate(config);
#endif


    std::istringstream stream("video 49170/2 RTP/AVP 31");

    std::string str("m=video 49170/2 RTP/AVP 31");

    boost::char_separator<char> sep;
    boost::tokenizer<boost::char_separator<char>> tok(str, sep);

    for (auto itor = tok.begin(); itor != tok.end(); ++itor)
        std::cout << *itor << std::endl;

    try
    {
        auto a = boost::lexical_cast<uint16_t>("12\r\n");
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 1;
}
