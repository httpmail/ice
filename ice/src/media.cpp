#include "media.h"

namespace {
    static const char BASE64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    static const uint16_t BASE64_CNT = sizeof(BASE64) / sizeof(BASE64[0]);

    std::string GenerateUserFrag()
    {
        std::string frag;
        for (uint16_t i = 0; i < STUN::sIceUfragLength; ++i)
            frag += BASE64[PG::GenerateRandom(0, BASE64_CNT - 1)];
        return frag;
    }

    std::string GenerateUserPwd()
    {
        std::string pwd;
        for (uint16_t i = 0; i < STUN::sIcePWDLength; ++i)
            pwd += BASE64[PG::GenerateRandom(0, BASE64_CNT - 1)];
        return pwd;
    }
}

namespace ICE {
    ICE::Media::Media() :
        m_icepwd(GenerateUserPwd()), m_iceufrag(GenerateUserFrag())
    {
    }

    ICE::Media::~Media()
    {
    }

    const Stream* Media::GetStreamById(uint16_t id) const
    {
        assert(id >= static_cast<uint16_t>(ClassicID::RTP));

        auto itor = m_Streams.find(id);
        return itor != m_Streams.end() ? itor->second : nullptr;
    }
}