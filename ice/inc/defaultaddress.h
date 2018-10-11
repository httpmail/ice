#pragma once

#include <boost/asio.hpp>

namespace ICE{
    class CDefaultAddress {
    private:
        CDefaultAddress();
        ~CDefaultAddress() {}

    public:
        static const CDefaultAddress&         Instance() { static CDefaultAddress sDefAddress; return sDefAddress;}
        const boost::asio::ip::tcp::endpoint& Endpoint() const noexcept { return m_endpoint; }
        std::string                           IPString() const noexcept { return m_endpoint.address().to_string(); }

    public:
        boost::asio::ip::tcp::endpoint GenerateDefaultEndpoint(bool bSupportIPv4 = true);

    private:
        const boost::asio::ip::tcp::endpoint m_endpoint;
    };
}
