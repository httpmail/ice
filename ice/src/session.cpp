#include "session.h"
#include "agent.h"
#include "media.h"
#include "sdp.h"
#include "candidate.h"

#include "pg_log.h"

#include <boost/asio.hpp>

#include <assert.h>

namespace {
    bool FormingCandidatePairs(const ICE::Session::MediaContainer& local_medias, const CSDP::RemoteMediaContainer& remote_medias, bool bControlling)
    {
        for (auto lmedias_itor = local_medias.begin(); lmedias_itor != local_medias.end(); ++lmedias_itor)
        {
            // find the same type media
            auto &media_name = lmedias_itor->first;
            auto rmedias_itor = remote_medias.find(media_name);
            if (rmedias_itor == remote_medias.end())
            {
                LOG_ERROR("Session", "remote has no [%s] media", media_name.c_str());
                return false;
            }

            // find the same component id stream
            auto rcandContainer   = rmedias_itor->second->Candidates();
            auto lstreams = lmedias_itor->second->GetStreams();
            for (auto lstream_itor = lstreams.begin(); lstream_itor != lstreams.end(); ++lstream_itor)
            {
                auto lcompId = lstream_itor->first;
                auto rcands_itor = rcandContainer.find(lcompId);

                if (rcands_itor == rcandContainer.end())
                {
                    LOG_ERROR("Session", "[%s] media no realted component id", media_name.c_str());
                    return false;
                }

                auto rcands = rcands_itor->second;
                auto lcands = lstream_itor->second->GetCandidates();

                for (auto rcand_itor = rcands->begin(); rcand_itor != rcands->end(); ++rcand_itor)
                {
                    auto rcand = *rcand_itor;
                    for (auto lcand_itor = lcands.begin(); lcand_itor != lcands.end(); ++lcand_itor)
                    {
                        auto lcand = lcand_itor->first;
                        assert(rcand->ComponentId() == lcand->ComponentId());

                        bool bSameProtocol = rcand->Protocol() == lcand->Protocol();
                        if (
                           ( bSameProtocol && rcand->Protocol() != ICE::Protocol::udp ) ||
                           (!bSameProtocol && (rcand->Protocol() == ICE::Protocol::udp || lcand->Protocol() == ICE::Protocol::udp)))
                        {
                            continue;
                        }
                        /*
                        RFC8445[6.1.2.3.  Computing Pair Priority and Ordering Pairs]
                        Let G be the priority for the candidate provided by the controlling agent.
                        Let D be the priority for the candidate provided by the controlled agent
                        pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
                        */
                        auto G = bControlling ? lcand->Priority() : rcand->Priority();
                        auto D = bControlling ? rcand->Priority() : lcand->Priority();

                        uint64_t priority = ((uint64_t)1 << 32) * std::min(G, D) + 2 * std::max(G, D) + (G > D ? 1 : 0);

                    }
                }
            }
        }
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
}