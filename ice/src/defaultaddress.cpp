#include "defaultaddress.h"

namespace ICE{
    CDefaultAddress::CDefaultAddress() :
        m_endpoint(GenerateDefaultEndpoint())
    {
    }

    boost::asio::ip::tcp::endpoint CDefaultAddress::GenerateDefaultEndpoint(bool bSupportIPv4 /*= true*/)
    {
        using boost::asio::ip::tcp;
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(boost::asio::ip::host_name(), "");
        tcp::resolver::iterator itor = resolver.resolve(query);
        tcp::resolver::iterator end;

        while (itor != end)
        {
            auto ep = *itor++;
            auto ep_address = ep.endpoint().address();

            /*
            Addresses from a loopback interface MUST NOT be included in the
            candidate addresses
             */
            if (ep_address.is_loopback())
                continue;

            if (ep_address.is_v6())
            {
                /*
                Deprecated IPv4-compatible IPv6 addresses [RFC4291] and IPv6 sitelocal
                unicast addresses [RFC3879] MUST NOT be included in the
                address candidates
                 */
                auto ipv6 = ep_address.to_v6();
                if (ipv6.is_v4_compatible() || ipv6.is_site_local())
                    continue;

                /*
                IPv4-mapped IPv6 addresses SHOULD NOT be included in the address
                candidates unless the application using ICE does not support IPv4
                (i.e., it is an IPv6-only application [RFC4038]).
                */
                if (bSupportIPv4 && ipv6.is_v4_mapped())
                    continue;
            }
            else if (0 == ep_address.to_string().find("169.254"))  // ipv4 lock-link
                continue;

            return ep;
        }

        assert(0); // read configure file
        return tcp::endpoint();
    }
}