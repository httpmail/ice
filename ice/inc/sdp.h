#pragma once

#include <stdint.h>

#include <unordered_set>
#include <unordered_map>
#include <string>

namespace ICE {
    class Candidate;
}

namespace ICE {
    class Session;
}

class CSDP {
public:
    class RemoteMedia {
    public:
        using CandContainer     = std::unordered_set<ICE::Candidate*>;
        using ComponentCands    = std::unordered_map<uint8_t, CandContainer*>;

    public:
        RemoteMedia(const std::string& type, const std::string& pwd, const std::string& ufrag) :
            m_type(type), m_icepwd(pwd), m_iceufrag(ufrag)
        {
        }

        virtual ~RemoteMedia();

        const std::string& Type() const { return m_type; }
        const ComponentCands& Candidates() const { return m_Cands; }

        bool AddHostCandidate(uint8_t compId, uint32_t pri, const std::string& foundation, const std::string& baseIP, uint16_t basePort);

        bool AddSrflxCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort);

        bool AddPrflxCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort);

        bool AddRelayCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& baseIP, uint16_t basePort,
            const std::string& relatedIP, uint16_t relatedPort);

    private:
        bool AddCandidate(uint8_t compId, STUN::Candidate* can);

    private:
        const std::string   m_icepwd;
        const std::string   m_iceufrag;
        const std::string   m_type;
        ComponentCands      m_Cands;
    };

public:
    using RemoteMediaContainer = std::unordered_map<std::string, RemoteMedia*>;
    using ConnectContainer     = std::unordered_map<std::string, bool>; /* IPV*/

public:
    CSDP();
    virtual ~CSDP();

public:
    bool Decode(const std::string& offer);
    bool Encode(const ICE::Session & session, std::string& offer);
    const RemoteMediaContainer& GetRemoteMedia() const { return m_RemoteMedias; }

private:
    RemoteMedia* DecodeMediaLine(const std::string& mediaLine, bool bSesUfragPwdExisted);
    bool DecodeCLine(const std::string& cline);

private:
    RemoteMediaContainer m_RemoteMedias;
    std::string          m_IcePwd;
    std::string          m_IceUfrag;
    ConnectContainer     m_Cline;
};