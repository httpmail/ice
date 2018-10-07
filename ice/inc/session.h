#pragma once

#include <set>

class CMedia;
class CCandidate;
class CPeer;

class CSession {
private:
    using MediaContainer     = std::set<CMedia*>;
    using CandidateContainer = std::set<CCandidate*>;
    using CPeerContainer     = std::set<CPeer*>;

public:
    CSession();
    virtual ~CSession();

private:
    MediaContainer      m_Media;
    CandidateContainer  m_Candidates;
    CPeerContainer      m_Peers;
};