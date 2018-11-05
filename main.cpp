

//#include <boost/asio.hpp>

#include <stdint.h>
#include <boost/asio.hpp>

class Abc {
public:
    union
    {
        struct {
            uint8_t     m_Number : 8;
            uint8_t     m_Class : 8;
            uint32_t : 8;
            uint32_t : 8;
        }details;

        uint32_t value;
    };
};


struct  Test
{
    uint8_t m_Number : 8;
    uint8_t m_Class : 3;
    uint32_t : 5;
    uint32_t : 8;
    uint32_t : 8;
};

struct Header {
    uint16_t type : 16;
    uint16_t length : 16;
};
int main() {
    Abc a;
 
    a.value = 0;
    a.details.m_Class = 4;
    a.details.m_Number = 1;

    uint8_t x[100] = { 0x01,0x11,0x00,0x2c };

    Header header = reinterpret_cast<Header*>(x)[0];

    header.type = boost::asio::detail::socket_ops::network_to_host_short(header.type);
    header.length = boost::asio::detail::socket_ops::network_to_host_short(header.length);

    return 1;
}
