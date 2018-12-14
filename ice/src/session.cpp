#include "session.h"
#include "agent.h"
#include "media.h"
#include "channel.h"
#include "candidate.h"
#include "pg_log.h"

#include <boost/asio.hpp>

#include <assert.h>

namespace ICE {
    Session::Session() :
        m_Config(PG::GenerateRandom64())
    {
    }

    Session::~Session()
    {
    }

    bool Session::MakeOffer(std::string & offer)
    {
#if 0
        //TODO Gathering MUST be DONE
        std::ostringstream offer_stream;

        bool isIPv4 = boost::asio::ip::address::from_string(m_DefaultIP).is_v4();

        // encode "v" line
        offer_stream << SDPDEF::v_line
            << "0" << SDPDEF::CRLF;

        // encode "o" line
        offer_stream << SDPDEF::o_line
            << m_Config.UserName() << " "
            << std::chrono::steady_clock::now().time_since_epoch().count() << " "
            << std::chrono::steady_clock::now().time_since_epoch().count() << " "
            << SDPDEF::nettype << " "
            << SDPDEF::addrtype(isIPv4) << " "
            << m_DefaultIP << SDPDEF::CRLF;

        // encode "s" line
        offer_stream << SDPDEF::s_line
            << m_Config.SessionName() << SDPDEF::CRLF;

        // encode "c" line
        offer_stream << SDPDEF::c_line
            << SDPDEF::nettype << " "
            << SDPDEF::addrtype(isIPv4) << " "
            << m_DefaultIP << SDPDEF::CRLF;

        // encode "t" line
        offer_stream << SDPDEF::t_line
            << 0 << " "
            << 0 << SDPDEF::CRLF;

        for (auto itor = m_Medias.begin(); itor != m_Medias.end(); ++itor)
        {
            auto *rtp = itor->second->GetStreamById(static_cast<uint16_t>(Media::ClassicID::RTP));

            assert(rtp);

            // encode "m" line
            offer_stream << SDPDEF::m_line
                << itor->first << " "
                << rtp->GetHostPort() << " "
                << rtp->GetTransportProtocol() << " "
                << 0 << SDPDEF::CRLF;

            auto *rtcp = itor->second->GetStreamById(static_cast<uint16_t>(Media::ClassicID::RTCP));
            assert(rtcp);

            // encode "rtcp" line
            offer_stream << SDPDEF::rtcp_line
                << rtcp->GetHostPort() << SDPDEF::CRLF;

            // encode "a=ice-pwd"
            offer_stream << SDPDEF::icepwd_line
                << itor->second->IcePwd() << SDPDEF::CRLF;

            //encode "a=ice-ufrag"
            offer_stream << SDPDEF::iceufrag_line
                << itor->second->IceUfrag() << SDPDEF::CRLF;

            //encode "a=candidate"
            auto & stream = itor->second->GetStreams();
            for (auto stream_itor = stream.begin(); stream_itor != stream.end(); ++stream_itor)
            {
                auto& cands = stream_itor->second->GetCandidates();
                const char* transport = SDPDEF::Transport(stream_itor->second->IsUDP());

                for (auto& cand = cands.begin(); cand != cands.end(); ++cand)
                {
                    /*
                    rfc5245
                    15.1.  "candidate" Attribute
                    */
                    offer_stream << SDPDEF::candidate_line
                        << cand->first->Foundation() << " "
                        << cand->first->ComponentId() << " "
                        << transport << " "
                        << cand->first->Priority() << " "
                        << cand->first->TransationIP() << " "
                        << cand->first->TransationPort() << " "
                        << SDPDEF::candtype << " "
                        << cand->first->TypeName();

                    if (!cand->first->IsHost())
                    {
                        offer_stream << " "
                            << SDPDEF::reladdr << " "
                            << cand->first->RelatedIP() << " "
                            << SDPDEF::relport << " "
                            << cand->first->RelatedPort();
                    }
                    offer_stream << SDPDEF::CRLF;
                }
            }
        }
#endif
        return true;
    }

    bool Session::MakeAnswer(const std::string & remoteOffer, std::string & answer)
    {
        return true;
    }
}