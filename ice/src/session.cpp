#include "session.h"
#include "agent.h"
#include "media.h"
#include "sdp.h"
#include "candidate.h"

#include "pg_log.h"

#include <boost/asio.hpp>

#include <assert.h>

namespace {
    using namespace ICE;
    bool FormingCandidatePairs(Session::CandPeerContainer& candPeers, const Media &lMedia, const CSDP::RemoteMedia& rMedia, bool bControlling)
    {
        auto lstream_container = lMedia.GetStreams();
        auto rcands_container = rMedia.Candidates();

        for (auto lstream_itor = lstream_container.begin(); lstream_itor != lstream_container.end(); ++lstream_itor)
        {
            auto rcands_itor = rcands_container.find(lstream_itor->first);
            if (rcands_itor == rcands_container.end())
            {
                LOG_ERROR("Session", "remote candidates has no corresponding +local candidate [%d]", lstream_itor->first);
                return false;
            }

            auto rcands_container = rcands_itor->second;
            assert(rcands_container);

            auto &lstream = lstream_itor->second;
            assert(lstream);

            auto lcands_container = lstream->GetCandidates();
            for (auto rcand_itor = rcands_container->begin(); rcand_itor != rcands_container->end(); ++rcands_itor)
            {
                auto rcand = *rcand_itor;
                assert(rcand);

                for (auto lcand_itor = lcands_container.begin(); lcand_itor != lcands_container.end(); ++lcand_itor)
                {
                    auto lcand = lcand_itor->first;
                    assert(lcand && lcand->ComponentId() == lstream_itor->first);
                    assert(lcand->ComponentId() == rcand->ComponentId());

                    auto lcand_family = boost::asio::ip::address::from_string(lcand->TransationIP()).is_v4();
                    auto rcand_family = boost::asio::ip::address::from_string(rcand->TransationIP()).is_v4();
                    if ((lcand_family == rcand_family) &&
                        (lcand->Protocol() == rcand->Protocol() && lcand->Protocol() == Protocol::udp) ||
                        (lcand->Protocol() != rcand->Protocol() && lcand->Protocol() != Protocol::udp && rcand->Protocol() != Protocol::udp))
                    {
                        /*
                        RFC8445[6.1.2.3.  Computing Pair Priority and Ordering Pairs]
                        Let G be the priority for the candidate provided by the controlling agent.
                        Let D be the priority for the candidate provided by the controlled agent
                        pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
                        */
                        auto G = bControlling ? lcand->Priority() : rcand->Priority();
                        auto D = bControlling ? rcand->Priority() : lcand->Priority();

                        uint64_t priority = ((uint64_t)1 << 32) * std::min(G, D) + 2 * std::max(G, D) + (G > D ? 1 : 0);
                        auto itor = candPeers.find(priority);
                        assert(itor == candPeers.end());
                        if (candPeers.insert(std::make_pair(priority, Session::CandidatePeer(priority, lcand, rcand))).second)
                        {
                            LOG_ERROR("Session", "Cannot Create Peer");
                        }
                    }
                }
            }
        }
        return true;
    }
}

namespace ICE {
    Session::Session(const std::string& defaultIP) :
        m_Config(PG::GenerateRandom64(), defaultIP)
    {
    }

    Session::~Session()
    {
    }

    bool Session::CreateMedia(const MediaAttr& mediaAttr, const CAgentConfig& config)
    {
        if (m_Medias.end() != m_Medias.find(mediaAttr.m_Name))
        {
            LOG_WARNING("Session", "Media %s already existed", mediaAttr.m_Name);
            return false;
        }

        std::auto_ptr<Media> media(new Media);
        if (!media.get())
        {
            LOG_ERROR("Session", "Not Enough memory to create Media");
            return false;
        }


        for (auto itor = mediaAttr.m_StreamAttrs.begin(); itor != mediaAttr.m_StreamAttrs.end(); ++itor)
        {
            if (!media->CreateStream(itor->m_CompId, itor->m_Protocol, itor->m_HostIP, itor->m_HostPort, config))
            {
                LOG_ERROR("Session", "Media [%s] Create Stream failed [%d] [%s:%d]", mediaAttr.m_Name, itor->m_CompId, itor->m_HostIP.c_str(), itor->m_HostPort);
                return false;
            }
        }

        if (!m_Medias.insert(std::make_pair(mediaAttr.m_Name, media.get())).second)
        {
            LOG_ERROR("Session", "Create Media Failed");
            return false;
        }

        media.release();
        return true;
    }

    bool Session::ConnectivityCheck(const std::string & offer)
    {
        CSDP sdp;
        if (!sdp.Decode(offer))
        {
            LOG_ERROR("Session", "Invalid Offer");
            return false;
        }

        auto& remoteMedia = sdp.GetRemoteMedia();

        for (auto local_itor = m_Medias.begin(); local_itor != m_Medias.end(); ++local_itor)
        {

            auto rmedia_itor = remoteMedia.find(local_itor->first);
            if (rmedia_itor == remoteMedia.end())
            {
                LOG_ERROR("Session", "local Media[%s] has no corresponding remote media", local_itor->first.c_str());
                return false;
            }

            auto& local_stream = local_itor->second->GetStreams();

            for (auto lstream_itor = local_stream.begin(); lstream_itor != local_stream.end(); ++lstream_itor)
            {
                auto& rcands = rmedia_itor->second->Candidates();
                for (auto rcand_itor = rcands.begin(); rcand_itor != rcands.end(); ++rcand_itor)
                {
                    // find the same component id
                    auto stream_itor = local_stream.find(rcand_itor->first);
                    if (stream_itor == local_stream.end())
                    {
                        LOG_ERROR("Session", "local media[%s] has no related component id:[%d] ", local_itor->first.c_str(), rcand_itor->first);
                        return false;
                    }

                    auto stream = stream_itor->second;
                    auto& lcands = stream->GetCandidates();
                    for (auto lcand_itor = lcands.begin(); lcand_itor != lcands.end(); ++lcand_itor)
                    {
                        auto lcand = lcand_itor->first;
                        assert(lcand->ComponentId() == rcand_itor->first);
                    }
                }
            }
        }
    }

    bool Session::MakeOffer(std::string & offer)
    {
        CSDP sdp;
        return sdp.Encode(*this, offer);
    }

    bool Session::MakeAnswer(const std::string & remoteOffer, std::string & answer)
    {
        return true;
    }
    Session::CandidatePeer::CandidatePeer(uint64_t PRI, const STUN::Candidate * lcand, const STUN::Candidate * rcand)
    {
        assert(lcand && rcand);
        assert(lcand->ComponentId() == rcand->ComponentId());
        assert((lcand->Protocol() == rcand->Protocol() && lcand->Protocol() == Protocol::udp) ||
            (lcand->Protocol() != rcand->Protocol() && lcand->Protocol() != Protocol::udp && rcand->Protocol() != Protocol::udp));
    }

    Session::CandidatePeer::~CandidatePeer()
    {
    }
}