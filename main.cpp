
#include "pg_log.h"
#include "pg_buffer.h"

#include "channel.h"
#include <thread>
#include <iostream>

using boost::asio::ip::tcp;

void Server(void)
{
    boost::asio::io_service io_service;
    tcp::acceptor acceptor(io_service, tcp::endpoint(boost::asio::ip::address::from_string("fe80::4072:64f3:b7ca:1a0%9"),1234));


    std::cout << "server :" << acceptor.local_endpoint().address().to_string() << std::endl;
    while (1)
    {
        tcp::socket socket(io_service);
        acceptor.accept(socket);
    }
}

int main(void)
{
    char tmp[256];

    std::string read_info;
    const std::string write_info("0123456789");

    PG::circular_buffer buf(10);

    buf.write(write_info.data(), write_info.length());

    int read_bytes = buf.read(tmp, 3);
    std::cout << std::string(tmp, read_bytes) << std::endl;

    read_bytes = buf.read(tmp, 3);
    std::cout << std::string(tmp, read_bytes) << std::endl;

    read_bytes = buf.read(tmp, 3);
    std::cout << std::string(tmp, read_bytes) << std::endl;

    buf.write(write_info.data(), write_info.length());
    read_bytes = buf.read(tmp, write_info.length());

    std::cout << std::string(tmp, read_bytes) << std::endl;

    boost::asio::io_service io_service;
    tcp::resolver resolver(io_service);
    tcp::resolver::query query(boost::asio::ip::host_name(), "");
    tcp::resolver::iterator iter = resolver.resolve(query);
    tcp::resolver::iterator end;

    auto thread = std::thread(Server);

    while (iter != end)
    {
        tcp::endpoint ep = *iter++;

        std::cout << ep.address().to_string();

        if (ep.address().is_v4())
        {
            std::cout << " v4";
            auto ip_v4 = ep.address().to_v4();
        }
        else if (ep.address().is_v6())
        {
            std::cout << " v6";
            auto ip_v6 = ep.address().to_v6();
            if (ip_v6.is_link_local())
                std::cout << " link_local";
            if (ip_v6.is_v4_compatible())
                std::cout << " v4_compatible";
            if (ip_v6.is_v4_mapped())
                std::cout << " v4_mapped";
        }

        if (ep.address().is_loopback())
            std::cout << " loopback";
        if (ep.address().is_multicast())
            std::cout << " multicast";
        if (ep.address().is_unspecified())
            std::cout << " unspecified";

        std::cout << ep.data() << std::endl;

        tcp::socket socket(io_service, ep);
        std::string ipStr = ep.address().is_v4() ? "127.0.0.1" : "1::1";
        tcp::endpoint remote(boost::asio::ip::address::from_string(ep.address().to_string()), 1234);

        try
        {
            tcp::socket _socket(io_service);
            _socket.connect(remote);
            std::cout << " connectd:" << remote.address().to_string() << ":" << remote.port() << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cout << " connect failed: " << e.what() << std::endl;
        }
        std::cout << std::endl;
    }

    tcp::endpoint e;
    std::cout << e.data() << std::endl;
    std::cout << e.address().to_string() << std::endl;
    std::cout << e.address().is_unspecified() << std::endl;
    while (1);
    return 0;
}