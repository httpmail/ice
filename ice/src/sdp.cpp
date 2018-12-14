#include "sdp.h"
#include "candidate.h"
#include "pg_log.h"

#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>

#include <sstream>
#include <assert.h>

namespace SDPDEF {
    static const std::string nettype = "IN";
    static const std::string candtype = "typ";
    static const std::string reladdr = "raddr";
    static const std::string relport = "rport";
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
    static const std::string host_cand_type = "host";
    static const std::string srflx_cand_type = "srflx";
    static const std::string prflx_cand_type = "prflx";
    static const std::string relay_cand_type = "relay";
    static const std::string typ = "typ";
    static const uint16_t min_cand_content_num = 8;
    static const uint16_t nonhost_cand_content_num = 12;
    static const uint16_t media_content_num = 4;

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
    enum class CandAttrIndex : uint8_t {
        foundation = 0,
        compId,
        transport, /*UDP TCP*/
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

    enum class MediaAttrIndex : uint8_t {
        media = 0,
        port,
        proto,
        fmt,
    };

    static const boost::char_separator<char> whitespace_separator(" ");
    static const boost::char_separator<char> slash_separator("/");

    using CharToken = boost::tokenizer<boost::char_separator<char>>;

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

CSDP::CSDP()
{
}

CSDP::~CSDP()
{
}

/*
    v=0
    o=jdoe 2890844526 2890842807 IN IP4 $L-PRIV-1.IP
    s=
    c=IN IP4 $NAT-PUB-1.IP
    t=0 0
    a=ice-pwd:asd88fgpdd777uzjYhagZg
    a=ice-ufrag:8hhY
    m=audio $NAT-PUB-1.PORT RTP/AVP 0
    b=RS:0
    b=RR:0
    a=rtpmap:0 PCMU/8000
    a=candidate:1 1 UDP 2130706431 $L-PRIV-1.IP $L-PRIV-1.PORT typ
    host
    a=candidate:2 1 UDP 1694498815 $NAT-PUB-1.IP $NAT-PUB-1.PORT typ
    srflx raddr $L-PRIV-1.IP rport $L-PRIV-1.PORT
*/

bool CSDP::Decode(const std::string & offer)
{
    // decode c-line
    auto pos = offer.find(SDPDEF::c_line);
    if (!SDPDEF::IsValidAttrPos(pos) || !DecodeCLine(offer.substr(pos, offer.find(SDPDEF::CRLF, pos))))
    {
        LOG_ERROR("CSDP", "Invalid c-line");
        return false;
    }

    // check if ice-pwd and ice-ufrag existed in session section
    bool bUfragPwdExisted = false;
    auto mline_pos = offer.find(SDPDEF::m_line);
    if (SDPDEF::IsValidAttrPos(mline_pos))
    {
        LOG_ERROR("SDP", "Invlaid m-line");
        return false;
    }


    auto session_section = offer.substr(0, mline_pos);
    auto ice_pwd_pos = session_section.find(SDPDEF::icepwd_line);
    auto ice_ufrag_pos = session_section.find(SDPDEF::iceufrag_line);

    if (SDPDEF::IsValidAttrPos(ice_pwd_pos) != SDPDEF::IsValidAttrPos(ice_ufrag_pos))
    {
        LOG_ERROR("SDP", "invalid ice-pwd, ice-ufrag attribute");
        return false;
    }

    if (SDPDEF::IsValidAttrPos(ice_pwd_pos))
    {
        bUfragPwdExisted = true;
    }

    do
    {
        auto next_mline_pos = offer.find(SDPDEF::m_line, mline_pos + SDPDEF::m_line.length());

        // there is another mline 
        if (next_mline_pos != std::string::npos && next_mline_pos != 0)
        {
            LOG_ERROR("SDP", "Invalid next_mline_pos");
            return false;
        }

        auto media_line = offer.substr(mline_pos, next_mline_pos);
        if (!DecodeMediaLine(media_line, bUfragPwdExisted))
        {
            LOG_ERROR("SDP", "Decode Media Line Error");
            return false;
        }
        mline_pos = next_mline_pos;
    } while (SDPDEF::IsValidAttrPos(mline_pos));

    return true;
}

CSDP::RemoteMedia* CSDP::DecodeMediaLine(const std::string & mediaLine, bool bUfragPwdExisted)
{
    assert(mediaLine.find(SDPDEF::m_line) == 0 && mediaLine.find(SDPDEF::m_line) != std::string::npos);

    using Content = std::vector<std::string>;

    // decode "m="
    std::string info(mediaLine.substr(mediaLine.find(SDPDEF::CRLF, SDPDEF::m_line.length())));

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
    if (media_content.size() < SDPDEF::media_content_num)
    {
        LOG_ERROR("SDP", "Decode SDP, illegal m= %s", info.c_str());
        return nullptr;
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
            LOG_WARNING("SDP", "Decode SDP, illegal rtcp content a=rtcp:%s", rtcp_content);
            return nullptr;
        }
    }

    /*
    RFC5245[15.4.]
    decode ice-ufrag and ice-pwd
    */
    auto ice_ufrag_pos = mediaLine.find(SDPDEF::iceufrag_line);
    auto ice_pwd_pos = mediaLine.find(SDPDEF::icepwd_line);

    bool bUfragExisted = SDPDEF::IsValidAttrPos(ice_ufrag_pos);
    bool bPwdExisted = SDPDEF::IsValidAttrPos(ice_pwd_pos);

    if ((bUfragExisted != bPwdExisted) || (!bUfragPwdExisted && !bUfragExisted))
    {
        LOG_ERROR("Session", "Decode SDP, illegal ufrag or pwd");
        return nullptr;
    }

    if (bUfragExisted)
    {
        assert(bPwdExisted);
        mediaLine.substr(ice_ufrag_pos + SDPDEF::iceufrag_line.length(), mediaLine.find(SDPDEF::CRLF, ice_ufrag_pos) - ice_ufrag_pos - SDPDEF::iceufrag_line.length());
        mediaLine.substr(ice_pwd_pos + SDPDEF::icepwd_line.length(), mediaLine.find(SDPDEF::CRLF, ice_pwd_pos) - ice_pwd_pos - SDPDEF::icepwd_line.length());
    }
    const std::string ice_ufrag = "";
    const std::string ice_pwd = "";

    /*
    RFC5245[15.1.  "candidate" Attribute]
    Decode a=candidate
    */

    std::auto_ptr<RemoteMedia> remoteMedia(new RemoteMedia(media_content[static_cast<uint16_t>(SDPDEF::MediaAttrIndex::media)],ice_pwd, ice_ufrag));

    for (auto cand_finder = mediaLine.find(SDPDEF::candidate_line); SDPDEF::IsValidAttrPos(cand_finder);
        cand_finder = mediaLine.find(SDPDEF::candidate_line, cand_finder + SDPDEF::candidate_line.length()))
    {
        assert(cand_finder == 0);
        auto cand_end_pos = mediaLine.find(SDPDEF::CRLF, cand_finder);

        Content cand_content;
        SDPDEF::CharToken token(mediaLine.substr(cand_finder + SDPDEF::candidate_line.length(), cand_end_pos - cand_finder - SDPDEF::candidate_line.length()));

        for (auto itor = token.begin(); itor != token.end(); ++itor)
            cand_content.push_back(*itor);

        // check content number
        if (cand_content.size() < SDPDEF::min_cand_content_num)
        {
            LOG_ERROR("Session", "Decode SDP, invalid candidate[host size invalid]: %s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        // check 'typ'
        if (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::typ)] != SDPDEF::typ)
        {
            LOG_ERROR("Session", "Decode SDP, candidate typ Must be \'typ\' :%s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        // check 'candidate_type' must be 'host, srflx,prflx,relay'
        auto candtype = cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::candtype)];
        if (!SDPDEF::IsValidCandType(candtype))
        {
            LOG_ERROR("Session", "Decode SDP, invalid candidate type :%s", candtype.c_str());
            return nullptr;
        }

        // if is non-host-candidate, check content number
        bool isHostCand = (candtype == SDPDEF::host_cand_type);
        if (!isHostCand && cand_content.size() < SDPDEF::nonhost_cand_content_num)
        {
            LOG_ERROR("Session", "Decode SDP, invalid candidate[non-host size invalid]: %s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        // check 'raddr' and 'rport '
        if (!isHostCand &&
            (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::raddr)] != SDPDEF::reladdr) &&
            (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::rport)] != SDPDEF::relport))
        {
            LOG_ERROR("Session", "Decode SDP, invalid raddr or rport: %s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::transport)];

        uint32_t compId, priority;
        uint16_t conn_port(0), conn_rport(0);
        try
        {
            priority = boost::lexical_cast<uint32_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::priority)]);
            compId = boost::lexical_cast<uint8_t>(cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::compId)]);
            conn_port = boost::lexical_cast<uint16_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_port)]);
            if (!isHostCand)
                conn_rport = boost::lexical_cast<uint16_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_rport)]);
        }
        catch (const std::exception&)
        {
            LOG_ERROR("Session", "Decode SDP, invalid priority, component, or port");
            return nullptr;
        }

        if (candtype == SDPDEF::host_cand_type)
        {
            if (!remoteMedia->AddHostCandidate(compId, priority,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::foundation)],
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_addr)],
                conn_port))
            {
                LOG_ERROR("SDP", "add host candidate failed");
                return nullptr;
            }
        }
        else if (candtype == SDPDEF::srflx_cand_type)
        {
            if (!remoteMedia->AddSrflxCandidate(compId, priority,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::foundation)],
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_addr)],conn_port,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_raddr)], conn_rport))
            {
                LOG_ERROR("SDP", "add srflx candidate failed");
                return nullptr;
            }
        }
        else if (candtype == SDPDEF::relay_cand_type)
        {
            if (!remoteMedia->AddRelayCandidate(compId, priority,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::foundation)],
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_addr)], conn_port,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_raddr)], conn_rport))
            {
                LOG_ERROR("SDP", "add relay candidate failed");
                return nullptr;
            }
        }
    }

    return remoteMedia.release();
}

bool CSDP::DecodeCLine(const std::string & cline)
{
    return false;
}


CSDP::RemoteMedia::~RemoteMedia()
{
    for (auto itor = m_Cands.begin(); itor != m_Cands.end(); ++itor)
    {
        assert(itor->second);

        for (auto cand_itor = itor->second->begin(); cand_itor != itor->second->end(); ++cand_itor)
            delete *cand_itor;

        delete itor->second;
    }
}

bool CSDP::RemoteMedia::AddHostCandidate(uint8_t compId, uint32_t pri, const std::string & foundation, const std::string & baseIP, uint16_t basePort)
{
    std::auto_ptr<STUN::HostCandidate> cand(new STUN::HostCandidate(compId, pri, foundation, baseIP, basePort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }
    return false;
}

bool CSDP::RemoteMedia::AddSrflxCandidate(uint8_t compId, uint32_t pri, const std::string & foundation, const std::string & baseIP, uint16_t basePort, const std::string & relatedIP, uint16_t relatedPort)
{
    std::auto_ptr<STUN::SrflxCandidate> cand(new STUN::SrflxCandidate(compId, pri, foundation, baseIP, basePort, relatedIP, relatedPort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }
    return false;
}

bool CSDP::RemoteMedia::AddPrflxCandidate(uint8_t compId, uint32_t pri, const std::string & foundation, const std::string & baseIP, uint16_t basePort, const std::string & relatedIP, uint16_t relatedPort)
{
    std::auto_ptr<STUN::SrflxCandidate> cand(new STUN::SrflxCandidate(compId, pri, foundation, baseIP, basePort, relatedIP, relatedPort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }

    return false;
}

bool CSDP::RemoteMedia::AddRelayCandidate(uint8_t compId, uint32_t pri, const std::string & foundation, const std::string & baseIP, uint16_t basePort, const std::string & relatedIP, uint16_t relatedPort)
{
    std::auto_ptr<STUN::RelayedCandidate> cand(new STUN::RelayedCandidate(compId, pri, foundation, baseIP, basePort, relatedIP, relatedPort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }

    return false;
}

bool CSDP::RemoteMedia::AddCandidate(uint8_t compId, STUN::Candidate *can)
{
    assert(can);
    auto itor = m_Cands.find(compId);

    CandContainer *container = nullptr;

    if (itor == m_Cands.end())
    {
        container = new CandContainer;
        if (!container || m_Cands.insert(std::make_pair(compId, container)).second)
        {
            LOG_ERROR("Session", "Not enough memory to create Candidate");
            delete container;
            return false;
        }
    }
    else
    {
        assert(itor->second);
        container = itor->second;
    }

    assert(container);

    if (!container->insert(can).second)
    {
        LOG_ERROR("Session", "Add Candidate Failed");
        return false;
    }

    return true;
}
