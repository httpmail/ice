
#include "candidate.h"
#include <functional>
#include <boost/function.hpp>
#include <boost/lexical_cast.hpp>

namespace ICE {
    uint32_t Candidate::ComputeFoundations(CandType type, const std::string & baseIP, const std::string & serverIP, ICE::Protocol protocol)
    {
        char buf[4]; /* the max_value of type is 256 */
        std::string hashStr(baseIP + serverIP);
        sprintf_s(buf, sizeof(buf), "%d", type);
        hashStr += buf;
        sprintf_s(buf, sizeof(buf), "%d", protocol);
        hashStr += buf;

        return std::hash<std::string>{}(hashStr);
    }
}