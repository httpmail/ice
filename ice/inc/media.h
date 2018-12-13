#pragma once

#include <set>
#include "stream.h"

namespace ICE {
    class Media {
    public:
        enum class ClassicID : uint16_t{
            RTP = 1,
            RTCP,
        };

    public:
        using StreamContainer = std::map<uint16_t, Stream*>;

    public:
        Media();
        virtual ~Media();

        const StreamContainer& GetStreams() const { return m_Streams; }
        const Stream* GetStreamById(uint16_t id) const;
        const std::string& IcePwd() const { return m_icepwd; }
        const std::string& IceUfrag() const { return m_iceufrag; }

    private:
        StreamContainer     m_Streams;
        const std::string   m_icepwd;
        const std::string   m_iceufrag;
    };
}