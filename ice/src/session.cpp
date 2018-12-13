#include "session.h"
#include "agent.h"
#include "media.h"
#include "channel.h"
#include "candidate.h"
#include "pg_log.h"

#include <boost/asio.hpp>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>

#include <sstream>
#include <assert.h>

#if 0
foundation = 1 * 32ice - char
component - id = 1 * 5DIGIT
transport = "UDP" / transport - extension
transport - extension = token; from RFC 3261
priority = 1 * 10DIGIT
cand - type = "typ" SP candidate - types
candidate - types = "host" / "srflx" / "prflx" / "relay" / token
rel - addr = "raddr" SP connection - address
rel - port = "rport" SP port
#endif

namespace SDPDEF {
    static const std::string nettype  = "IN";
    static const std::string candtype = "typ";
    static const std::string reladdr  = "raddr";
    static const std::string relport  = "rport";
    static const std::string v_line = "v=";
    static const std::string o_line = "o=";
    static const std::string m_line = "m=";
    static const std::string c_line = "c=";
    static const std::string s_line = "s=";
    static const std::string t_line = "t=";
    static const std::string candidate_line = "a=candidate:";
    static const std::string remotecand_line = "a=remote-candidates:";
    static const std::string icepwd_line = "a=ice-pwd:";
    static const std::string iceufrag_line = "ice-ufrag:";
    static const std::string rtcp_line = "rtcp:";
    static const std::string CRLF = "\r\n";
    static const std::string host_cand_type  = "host";
    static const std::string srflx_cand_type = "srflx";
    static const std::string prflx_cand_type = "prflx";
    static const std::string relay_cand_type = "relay";
    static const std::string typ = "typ";

    /*
    RFC5245 [15.1.  "candidate" Attribute]
    candidate-attribute   = "candidate" ":" foundation SP component-id SP
    transport SP
    priority SP
    connection-address SP     ;from RFC 4566
    port         ;port from RFC 4566
    SP cand-type
    [SP rel-addr]
    [SP rel-port]
    *(SP extension-att-name SP
    extension-att-value)
    */
    enum class CandAttrIndex : uint8_t{
        foundation = 0,
        compId,
        transport,
        priority,
        conn_addr,
        conn_port,
        typ,      /* 'typ' */
        candtype, /*"host" "srflx" "prflx" "relay"*/
        raddr,    /* 'raddr'*/
        conn_raddr,
        rport,    /*'rport'*/
        conn_rport, 
        max_support_attr
    };

    static const boost::char_separator<char> whitespace_separator(" ");
    static const boost::char_separator<char> slash_separator("/");

    using CharToken = boost::tokenizer<boost::char_separator<char>>;

    static const int16_t m_line_content_num(4);

    const char* addrtype(const std::string& ip)
    {
        return boost::asio::ip::address::from_string(ip).is_v4() ? "IPv4" : "IPv6";
    }

    const char* addrtype(bool isIPv4)
    {
        return isIPv4 ? "IPv4" : "IPv6";
    }

    const char* Transport(bool isUDP)
    {
        return isUDP ? "UDP" : "TCP";
    }

    bool IsValidAttrPos(std::string::size_type pos)
    {
        return pos != std::string::npos && pos == 0;
    }

    bool IsValidCandType(const std::string& candtype)
    {
        return candtype == host_cand_type ||
            candtype == srflx_cand_type ||
            candtype == prflx_cand_type ||
            candtype == relay_cand_type;
    }
}

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
        return true;
    }

    bool Session::MakeAnswer(const std::string & remoteOffer, std::string & answer)
    {
        return true;
    }

    bool Session::DecodeSDP(const std::string & offer)
    {
        // decode c-line
        auto finder = offer.find(SDPDEF::c_line);
        if (finder == std::string::npos || finder != 0)
        {
            LOG_ERROR("Session", "Decode SDP, c-line is illegal");
            return false;
        }
        std::istringstream c_line(offer.substr(finder, offer.find(SDPDEF::CRLF, finder)));


        // decode m-line
        finder = 0;
        while (std::string::npos != (finder = offer.find(SDPDEF::m_line, finder)))
        {
            // m-line MUST be at beginning of a line
            if (finder != 0)
            {
                LOG_ERROR("Session", "Decode SDP, m-line is illegal");
                return false;
            }

            // meida content
            DecodeMediaLine(offer.substr(finder, offer.find(SDPDEF::m_line, finder + SDPDEF::m_line.length())), false);
        }

        return true;
    }

    bool Session::DecodeMediaLine(const std::string & mediaLine, bool bUfragPwdExisted)
    {
        assert(mediaLine.find(SDPDEF::m_line) == 0 && mediaLine.find(SDPDEF::m_line) != std::string::npos);

        using Content = std::vector<std::string>;

        // decode "m="
        std::string info(mediaLine.substr(mediaLine.find(SDPDEF::CRLF, SDPDEF::m_line.length())));

        bool bMatched = false;
        for (auto itor = m_Medias.begin(); itor != m_Medias.end(); ++itor)
        {
            if (std::string::npos != info.find(itor->first))
            {
                bMatched = true;
                break;
            }
        }

        if (!bMatched)
        {
            LOG_WARNING("Session", "Decode SDP, there is no matched meida type for SDP: %s", mediaLine.c_str());
            return false;
        }


        SDPDEF::CharToken token(info, SDPDEF::whitespace_separator);

        Content media_content;
        for (auto itor = token.begin(); itor != token.end(); ++itor)
        {
            media_content.push_back(*itor);
        }

        /*
        rfc4566
        m=<media> <port>/<number of ports> <proto> <fmt>
        */
        if (media_content.size() != SDPDEF::m_line_content_num)
        {
            LOG_ERROR("Session", "Decode SDP, illegal m= %s", info.c_str());
            return false;
        }

        /*
        decode a=rtcp:
        */
        auto rtcp_pos = mediaLine.find(SDPDEF::rtcp_line);
        if (SDPDEF::IsValidAttrPos(rtcp_pos))
        {
            auto rtcp_content = mediaLine.substr(rtcp_pos + SDPDEF::rtcp_line.length(),
                mediaLine.find(SDPDEF::CRLF, rtcp_pos) - rtcp_pos - SDPDEF::rtcp_line.length());
            try
            {
                boost::lexical_cast<uint16_t>(mediaLine.substr(SDPDEF::rtcp_line.length()));
            }
            catch (const std::exception&)
            {
                LOG_WARNING("Session", "Decode SDP, illegal rtcp content a=rtcp:%s", rtcp_content);
                return false;
            }
        }

        /*
        RFC5245[15.4.]
        decode ice-ufrag and ice-pwd
         */
        auto ice_ufrag_pos  = mediaLine.find(SDPDEF::iceufrag_line);
        auto ice_pwd_pos    = mediaLine.find(SDPDEF::icepwd_line);

        bool bUfragExisted  = SDPDEF::IsValidAttrPos(ice_ufrag_pos);
        bool bPwdExisted    = SDPDEF::IsValidAttrPos(ice_pwd_pos);

        if ((bUfragExisted != bPwdExisted) || (!bUfragPwdExisted && !bUfragExisted))
        {
            LOG_ERROR("Session", "Decode SDP, illegal ufrag or pwd");
            return false;
        }

        if (bUfragExisted)
        {
            assert(bPwdExisted);
            mediaLine.substr(ice_ufrag_pos + SDPDEF::iceufrag_line.length(), mediaLine.find(SDPDEF::CRLF, ice_ufrag_pos) - ice_ufrag_pos - SDPDEF::iceufrag_line.length());
            mediaLine.substr(ice_pwd_pos + SDPDEF::icepwd_line.length(), mediaLine.find(SDPDEF::CRLF, ice_pwd_pos) - ice_pwd_pos - SDPDEF::icepwd_line.length());
        }

        /*
        RFC5245[15.1.  "candidate" Attribute]
         Decode a=candidate
         */
        for(auto cand_finder = mediaLine.find(SDPDEF::candidate_line); SDPDEF::IsValidAttrPos(cand_finder);
            cand_finder = mediaLine.find(SDPDEF::candidate_line,cand_finder + SDPDEF::candidate_line.length()))
        {
            assert(cand_finder == 0);
            auto cand_end_pos = mediaLine.find(SDPDEF::CRLF, cand_finder);

            Content cand_content;
            SDPDEF::CharToken token(mediaLine.substr(cand_finder + SDPDEF::candidate_line.length(), cand_end_pos - cand_finder - SDPDEF::candidate_line.length()));

            for (auto itor = token.begin(); itor != token.end(); ++itor)
            {
                cand_content.push_back(*itor);
            }

            if (cand_content.size() < static_cast<uint16_t>(SDPDEF::CandAttrIndex::candtype))
            {
                LOG_ERROR("Session", "Decode SDP, invalid candidate[size < min size]:%s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
                return false;
            }

            if (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::typ)] != SDPDEF::typ)
            {
                LOG_ERROR("Session", "Decode SDP, candidate typ Must be \'typ\' :%s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
                return false;
            }

            // check cand type
            auto candtype = cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::candtype)];
            if (!SDPDEF::IsValidCandType(candtype))
            {
                LOG_ERROR("Session", "Decode SDP, invalid candidate type :%s", candtype.c_str());
                return false;
            }

            // check if content is matched
            if ((candtype == SDPDEF::host_cand_type && cand_content.size() != (static_cast<uint16_t>(SDPDEF::CandAttrIndex::candtype) + 1)) ||
                (candtype != SDPDEF::host_cand_type && cand_content.size() < static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_rport)))
            {
                LOG_ERROR("Session", "Decode SDP, invalid candidate :%s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
                return false;
            }

            try
            {
                boost::lexical_cast<uint32_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::priority)]);
                boost::lexical_cast<uint16_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_port)]);

                // decode rel_port
                if (candtype != SDPDEF::host_cand_type)
                {
                    boost::lexical_cast<uint32_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_rport)]);
                }

            }
            catch (const std::exception&)
            {
                LOG_ERROR("Session", "Decode SDP, invalid priority or port");
                return false;
            }

            cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::foundation)];
            cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::compId)];
            cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::transport)];
            cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_addr)];
            cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::candtype)];


            

        }

        RemoteMedia remoteMedia;
        return true;
    }

    Session::RemoteMedia::RemoteMedia()
    {
    }

    Session::RemoteMedia::~RemoteMedia()
    {
    }

    void Session::RemoteMedia::AddHostCandidate(uint8_t compId, bool bUDP, const std::string & baseIP, uint16_t basePort)
    {
    }
    void Session::RemoteMedia::AddSrflxCandidate(uint8_t compId, bool bUDP, const std::string & baseIP, uint16_t basePort, const std::string & relatedIP, uint16_t relatedPort)
    {
    }
    void Session::RemoteMedia::AddPrflxCandidate(uint8_t compId, bool bUDP, const std::string & baseIP, uint16_t basePort, const std::string & relatedIP, uint16_t relatedPort)
    {
    }

    void Session::RemoteMedia::AddRelayCandidate(uint8_t compId, bool bUDP, const std::string & baseIP, uint16_t basePort, const std::string & relatedIP, uint16_t relatedPort)
    {
    }
}