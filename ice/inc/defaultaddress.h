#pragma once

#include <boost/asio.hpp>

namespace ICE{
    class CDefaultAddress {
    private:
        CDefaultAddress();
        ~CDefaultAddress() {}

    public:
        static const CDefaultAddress&         Instance() { static CDefaultAddress sDefAddress; return sDefAddress;}
        const boost::asio::ip::tcp::endpoint& Endpoint() const noexcept { assert(!m_endpoint.address().is_unspecified()); return m_endpoint; }
        std::string                           IPString() const noexcept { assert(!m_endpoint.address().is_unspecified()); return m_endpoint.address().to_string(); }
        bool                                  IsConfigured() const noexcept { return !m_endpoint.address().is_unspecified(); }

    public:
        bool GenerateDefaultEndpoint(const std::string& ip = "", bool bSupportIPv4 = true);

    private:
        boost::asio::ip::tcp::endpoint m_endpoint;
    };
}
