#pragma once

namespace ICE {
    class CCandidate;

    class CPeer {
    public:
        CPeer(CCandidate& local, CCandidate& remote);
        virtual ~CPeer();

    private:
        CCandidate& m_local;
        CCandidate& m_remote;
    };
}