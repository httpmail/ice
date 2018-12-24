#include "session.h"
#include "agent.h"
#include "media.h"
#include "sdp.h"
#include "candidate.h"

#include "pg_log.h"

#include <boost/asio.hpp>
#include <iostream>

#include <assert.h>

namespace {
    using namespace ICE;
    bool FormingCandidatePairs(Session::CandPeerContainer& candPeers, const Media &lMedia, const CSDP::RemoteMedia& rMedia, bool bControlling)
    {
        auto &lstream_container = lMedia.GetStreams();
        auto &rcomp_cands_container = rMedia.Candidates();

        for (auto lstream_itor = lstream_container.begin(); lstream_itor != lstream_container.end(); ++lstream_itor)
        {
            auto rcomp_cands_itor = rcomp_cands_container.find(lstream_itor->first);
            if (rcomp_cands_itor == rcomp_cands_container.end())
            {
                LOG_ERROR("Session", "remote candidates has no corresponding local candidate [%d]", lstream_itor->first);
                return false;
            }

            LOG_INFO("Session", "====> Make CompID [%d] pairs ", lstream_itor->first);
            auto rcands_container = rcomp_cands_itor->second;
            assert(rcands_container);

            auto &lstream = lstream_itor->second;
            assert(lstream);

            auto lcands_container = lstream->GetCandidates();
            for (auto rcand_itor = rcands_container->begin(); rcand_itor != rcands_container->end(); ++rcand_itor)
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

                        // find if there is dumplicate cand peer
                        bool bAddNewPeer = true;
                        auto dump_itor = candPeers.begin();
                        for (; dump_itor != candPeers.end(); ++dump_itor)
                        {
                            if (lcand->TransationPort() == dump_itor->second.LCandidate().TransationPort() &&
                                rcand->TransationPort() == dump_itor->second.RCandidate().TransationPort() &&
                                lcand->TransationIP() == dump_itor->second.LCandidate().TransationIP() &&
                                rcand->TransationIP() == dump_itor->second.RCandidate().TransationIP())
                            {
                                if (priority > dump_itor->first)
                                {
                                    bAddNewPeer = true;
                                    candPeers.erase(dump_itor);
                                }
                                else
                                {
                                    bAddNewPeer = false;
                                }
                                break;
                            }
                        }
                        if (bAddNewPeer && !candPeers.insert(std::make_pair(priority, Session::CandidatePeer(priority, lcand, rcand))).second)
                        {
                            LOG_ERROR("Session", "Insert Peer failed component [%d]", lstream_itor->first);
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

        LOG_ERROR("Session", "remote offer: %s", offer.c_str());

        auto& RemoteMedias = sdp.GetRemoteMedia();

        for (auto lmedia_itor = m_Medias.begin(); lmedia_itor != m_Medias.end(); ++lmedia_itor)
        {
            auto rmedia_itor = RemoteMedias.find(lmedia_itor->first);
            if (rmedia_itor == RemoteMedias.end())
            {
                LOG_ERROR("Session", "remote media has no [%s] media", lmedia_itor->first.c_str());
                return false;
            }

            assert(m_MediaCandPairs.find(lmedia_itor->first) == m_MediaCandPairs.end());

            std::auto_ptr<CandPeerContainer> CandPeers(new CandPeerContainer);
            if (!CandPeers.get())
            {
                LOG_ERROR("Session", "out of memory to create candidte peer container [%s]", lmedia_itor->first.c_str());
                return false;
            }

            if (!FormingCandidatePairs(*CandPeers.get(), *lmedia_itor->second, *rmedia_itor->second, m_Config.IsControlling()))
            {
                LOG_ERROR("Session", "Forming Candidate Pairs failed");
                return false;
            }

            if (!m_MediaCandPairs.insert(std::make_pair(lmedia_itor->first, CandPeers.get())).second)
            {
                LOG_ERROR("Session", "Insert Media Candidate Pairs failed");
                return false;
            }
            CandPeers.release();
        }


        assert(m_MediaCandPairs.size());

        for (auto media_cand_pairs_itor = m_MediaCandPairs.begin(); media_cand_pairs_itor != m_MediaCandPairs.end(); ++media_cand_pairs_itor)
        {
            LOG_INFO("*****", "%s => ", media_cand_pairs_itor->first.c_str());

            for (auto cand_pairs_itor = media_cand_pairs_itor->second->begin(); cand_pairs_itor != media_cand_pairs_itor->second->end(); ++cand_pairs_itor)
            {
                auto& lcand = cand_pairs_itor->second.LCandidate();
                auto& rcand = cand_pairs_itor->second.RCandidate();

                LOG_INFO("*****", "PRI: [%lld] [local: %s:%d, remote:%s,%d]", cand_pairs_itor->first,lcand.TransationIP().c_str(),lcand.TransationPort(), rcand.TransationIP().c_str(), rcand.TransationPort());
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
    Session::CandidatePeer::CandidatePeer(uint64_t PRI, const STUN::Candidate * lcand, const STUN::Candidate * rcand):
        m_LCand(lcand),m_RCand(rcand)
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