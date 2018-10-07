#include "channel.h"
#include "pg_log.h"
#include <boost/array.hpp>
#include <memory>

namespace ICE {

    //////////////////////// CTCPChannel Class //////////////////////////
    CTCPChannel::CTCPChannel() :
        m_socket(m_io_service)
    {
    }

    CTCPChannel::~CTCPChannel()
    {
    }

    std::string CTCPChannel::GetIPString() const noexcept
    {
        try
        {
            return m_socket.local_endpoint().address().to_string();
        }
        catch (const std::exception&)
        {
            return "";
        }
    }

    int CTCPChannel::GetPort() const noexcept
    {
        try
        {
            return m_socket.local_endpoint().port();
        }
        catch (std::exception&)
        {
            return 0;
        }
    }

    bool CTCPChannel::BindLocal(const std::string & ip, int port) noexcept
    {
        try
        {
            auto local_point = boost_tcp::endpoint(boost::asio::ip::address::from_string(ip), port);
            m_socket.open(local_point.protocol());
            m_socket.bind(local_point);
        }
        catch (std::exception& e)
        {
            LOG_ERROR("tcp-channel", "[%s:%d] bind error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
        return true;
    }

    bool CTCPChannel::BindRemote(const std::string & remote_ip, int port) noexcept
    {
        try 
        {
            m_socket.connect(boost_tcp::endpoint(boost::asio::ip::address::from_string(remote_ip), port));
        }
        catch (std::exception& e)
        {
            LOG_ERROR("tcp-channel", "[%s:%d] connect error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
        return true;
    }

    bool CTCPChannel::Write(const char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            boost::asio::write(m_socket, boost::asio::buffer(buffer, size), boost::asio::transfer_all(), error);
            if (boost::asio::error::eof == error)
            {
                LOG_INFO("tcp-channel","send error: [%s:%d] closed", 
                            m_socket.remote_endpoint().address().to_string().c_str(),
                            m_socket.remote_endpoint().port());
                return false;
            }
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("tcp-channel", "[%s : %d] Send error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
    }

    bool CTCPChannel::Read(char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            boost::asio::read(m_socket, boost::asio::buffer(buffer, size), boost::asio::transfer_all(), error);
            if (error == boost::asio::error::eof)
            {
                LOG_INFO("tcp-channel", "send error: [%s:%d] closed",
                    m_socket.remote_endpoint().address().to_string().c_str(),
                    m_socket.remote_endpoint().port());
                return false;
            }
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("tcp-channel", "[%s: %d] receive error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
    }


    bool CTCPServerChannel::BindLocal(const std::string & ip, int port) noexcept
    {
        try
        {
            m_acceptor.bind(boost_tcp::endpoint(boost::asio::ip::address::from_string(ip), port));
            return true;
        }
        catch (const boost::system::system_error& boost_error)
        {
            LOG_ERROR("tcp-server-channel", "BindLocal exception: %s", boost_error.what());
            return false;
        }
    }

    //////////////////////// CTCPServerChannel Class /////////////////////
    bool CTCPServerChannel::Listen(int backlog) noexcept
    {
        try
        {
            m_acceptor.listen(backlog);
            return true;
        }
        catch (const boost::system::system_error& boost_error)
        {
            LOG_ERROR("tcp-server-channel", "Listen exception: %s", boost_error.what());
            return false;
        }
    }

    CTCPChannel* CTCPServerChannel::Accept()
    {
        try
        {
            CTCPChannel c;
            std::auto_ptr<CTCPChannel> tcpChannel(new CTCPChannel());
            if (tcpChannel.get())
            {
                m_acceptor.accept(tcpChannel->Socket());
                return tcpChannel.release();
            }
            else
            {
                return nullptr;
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("tcp-server-channel", "Accept exception :%s", e.what());
            return nullptr;
        }
    }

    //////////////////////// CUDPChannel Class //////////////////////////
    CUDPChannel::CUDPChannel() :
        m_socket(m_io_service)
    {
    }

    CUDPChannel::~CUDPChannel()
    {
    }

    std::string CUDPChannel::GetIPString() const noexcept
    {
        try
        {
            return m_socket.local_endpoint().address().to_string();
        }
        catch (const std::exception&)
        {
            return "";
        }
    }

    int CUDPChannel::GetPort() const noexcept
    {
        try
        {
            return m_socket.local_endpoint().port();
        }
        catch (std::exception&)
        {
            return 0;
        }
    }

    bool CUDPChannel::BindLocal(const std::string & ip, int port) noexcept
    {
        try
        {
            auto local_point = boost_udp::endpoint(boost::asio::ip::address::from_string(ip), port);
            m_socket.open(local_point.protocol());
            m_socket.bind(local_point);
        }
        catch (std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s:%d] bind error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
        return true;
    }

    bool CUDPChannel::BindRemote(const std::string & remote_ip, int port) noexcept
    {
        try
        {
            m_socket.remote_endpoint() = boost_udp::endpoint(boost::asio::ip::address::from_string(remote_ip), port);
        }
        catch (std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s:%d] connect error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
        return true;
    }

    bool CUDPChannel::Write(const char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            m_socket.send_to(boost::asio::buffer(buffer, size), m_socket.remote_endpoint());
            if (boost::asio::error::eof == error)
            {
                LOG_INFO("udp-channel", "send error: [%s:%d] closed",
                    m_socket.remote_endpoint().address().to_string().c_str(),
                    m_socket.remote_endpoint().port());
                return false;
            }
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s : %d] Send error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
    }

    bool CUDPChannel::Read(char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            m_socket.receive_from(boost::asio::buffer(buffer, size), m_socket.remote_endpoint());
            if (error == boost::asio::error::eof)
            {
                LOG_INFO("udp-channel", "send error: [%s:%d] closed",
                    m_socket.remote_endpoint().address().to_string().c_str(),
                    m_socket.remote_endpoint().port());
                return false;
            }
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s: %d] receive error : %s", GetIPString().c_str(), GetPort(), e.what());
            return false;
        }
    }

    CAsyncTCPChannel::CAsyncTCPChannel(const std::string & unique_name) :
        CTCPChannel(), PG::MsgEntity(unique_name)
    {
        RegisterEvent(Event::write);
        RegisterEvent(Event::read);
    }
}
