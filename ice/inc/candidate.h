#pragma once

#include <string>
#include <boost/asio.hpp>

namespace ICE {
    class CChannel;

    class Candidate {
    public:
        enum class ChannelType {
            UDP,
            TCP_PASSIVE,
            TCP_ACT,
        };

    public:
        Candidate(uint8_t comp_id);
        virtual ~Candidate() {}
        virtual std::string TypeName()       const = 0;
        virtual uint8_t    TypePreference()  const = 0;
        virtual uint16_t   LocalPreference() const = 0;

        bool Initilize(ChannelType eType, const std::string& ip = "", int port = 0);

    protected:
        static CChannel*    CreateChannel(ChannelType eType);
        static uint32_t     CalcBKDRHash(const std::string& str);

    protected:
        uint32_t        m_priority;
        std::string     m_foundation;
        std::string     m_baseAddress;
        CChannel        *m_pChannel;
        const uint8_t   m_componet_id;
    };


    class HostCandidate : public Candidate {
    public:
        HostCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~HostCandidate() {}

        virtual std::string TypeName() const override final        { return "host"; }
        virtual uint8_t     TypePreference() const override final  { return 126; /* RFC5245 4.1.2.2 */}
        virtual uint16_t    LocalPreference() const override final { return 65535; }
    };

    class SrflxCandidate : public Candidate {
    public:
        SrflxCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~SrflxCandidate() {}

        virtual std::string TypeName() const override final        { return "srflx"; }
        virtual uint8_t     TypePreference() const override final  { return 100; /* RFC5245 4.1.2.2 */}
        virtual uint16_t    LocalPreference() const override final { return 65535;}

    protected:
        CChannel *m_pSflxChannel;
    };

    class RelayedCandidate : public Candidate {
        RelayedCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~RelayedCandidate() {}

        virtual std::string TypeName() const override final         { return "relayed"; }
        virtual uint8_t     TypePreference() const override final   { return 0; /* RFC5245 4.1.2.2 */}
        virtual uint16_t    LocalPreference() const override final  { return 65535; }

    protected:
        CChannel *m_pSflxChannel;
    };

    class PeerSrflxCandidate : public Candidate {
    public:
        PeerSrflxCandidate(uint8_t comp_id) : Candidate(comp_id) {}
        virtual ~PeerSrflxCandidate() {}

        virtual std::string TypeName() const override final       { return "srflx"; }
        virtual uint8_t     TypePreference() const override final { return 110; /* RFC5245 4.1.2.2 */ }
        virtual uint16_t    LocalPreference() const override final{ return 65535; }

    protected:
        CChannel *m_pSflxChannel;
    };
}

