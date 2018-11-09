#include "stunprotocol.h"
#include "pg_util.h"

#include <boost/asio.hpp>
#include <assert.h>

#if 0
    uint16_t PaddingN(uint8_t * buf, uint16_t length, uint16_t N)
    {
        assert((!(N &(N - 1))) && N); // n MUST be 2^n

        auto padding_size = (length + N - 1) & (~(N-1));
        if (padding_size)
            memset(buf + length, 0, length);
        return length + padding_size;
    }
#endif

namespace STUN {
    namespace PROTOCOL {
        uint16_t RFC5389::Encode(const ATTR::Priority& attr, uint8_t* buf)
        {
            return STUN_PROTOCOL::Encode(attr, buf);
        }

        uint16_t RFC5389::Encode(const ATTR::Role& attr, uint8_t* buf)
        {
            return STUN_PROTOCOL::Encode(attr, buf);
        }

        uint16_t RFC5389::Encode(const ATTR::UseCandidate& attr, uint8_t* buf)
        {
            return STUN_PROTOCOL::Encode(attr, buf);
        }

        void RFC5389::GenerateTransationId(STUN::TransId id)
        {
            reinterpret_cast<uint32_t*>(id)[0] = sMagicCookie;
            reinterpret_cast<uint32_t*>(&id[4])[0] = PG::GenerateRandom32();
            reinterpret_cast<uint64_t*>(&id[8])[0] = PG::GenerateRandom64();
        }
    }
}