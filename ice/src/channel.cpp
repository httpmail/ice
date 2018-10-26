#include "channel.h"
#include "pg_log.h"
#include <boost/array.hpp>
#include <memory>

namespace ICE {
    boost::asio::io_service CTCPChannel::sIOService;

    //////////////////////// CTCPChannel Class //////////////////////////
    CTCPChannel::CTCPChannel() :
        m_socket(sIOService)
    {
    }

    CTCPChannel::~CTCPChannel()
    {
    }

    std::string CTCPChannel::IPString() const noexcept
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

    int CTCPChannel::Port() const noexcept
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

    int CTCPChannel::Protocol() const noexcept
    {
        try
        {
            return m_socket.local_endpoint().protocol().protocol();
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
            LOG_ERROR("tcp-channel", "[%s:%d] bind error : %s", IPString().c_str(), Port(), e.what());
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
            LOG_ERROR("tcp-channel", "[%s:%d] connect error : %s", IPString().c_str(), Port(), e.what());
            return false;
        }
        return true;
    }

    int16_t CTCPChannel::Write(const char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            auto sent_bytes = boost::asio::write(m_socket, boost::asio::buffer(buffer, size), boost::asio::transfer_all(), error);
            if (boost::asio::error::eof == error)
            {
                LOG_INFO("tcp-channel","send error: [%s:%d] closed", 
                            m_socket.remote_endpoint().address().to_string().c_str(),
                            m_socket.remote_endpoint().port());
                return 0;
            }
            return sent_bytes;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("tcp-channel", "[%s : %d] Send error : %s", IPString().c_str(), Port(), e.what());
            return -1;
        }
    }

    int16_t CTCPChannel::Read(char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            auto recv_bytes = boost::asio::read(m_socket, boost::asio::buffer(buffer, size), boost::asio::transfer_all(), error);
            if (error == boost::asio::error::eof)
            {
                LOG_INFO("tcp-channel", "send error: [%s:%d] closed",
                    m_socket.remote_endpoint().address().to_string().c_str(),
                    m_socket.remote_endpoint().port());
                return 0;
            }
            return recv_bytes;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("tcp-channel", "[%s: %d] receive error : %s", IPString().c_str(), Port(), e.what());
            return -1;
        }
    }

    //////////////////////// CUDPChannel Class //////////////////////////
    CUDPChannel::CUDPChannel() :
        m_socket(sIOService)
    {
    }

    CUDPChannel::~CUDPChannel()
    {
    }

    std::string CUDPChannel::IPString() const noexcept
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

    int CUDPChannel::Port() const noexcept
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

    int CUDPChannel::Protocol() const noexcept
    {
        try
        {
            return m_socket.local_endpoint().protocol().protocol();
        }
        catch (const std::exception&)
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
            LOG_ERROR("udp-channel", "[%s:%d] bind error : %s", IPString().c_str(), Port(), e.what());
            return false;
        }
        return true;
    }

    bool CUDPChannel::BindRemote(const std::string & remote_ip, int port) noexcept
    {
        try
        {
            m_remote_endpoint = boost_udp::endpoint(boost::asio::ip::address::from_string(remote_ip), port);
        }
        catch (std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s:%d] bind remote error : %s", IPString().c_str(), Port(), e.what());
            return false;
        }
        return true;
    }

    int16_t CUDPChannel::Write(const char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            m_socket.send_to(boost::asio::buffer(buffer, size), m_remote_endpoint);
            if (boost::asio::error::eof == error)
            {
                LOG_INFO("udp-channel", "send error: [%s:%d] closed",
                    m_socket.remote_endpoint().address().to_string().c_str(),
                    m_socket.remote_endpoint().port());
                return 0;
            }
            return size;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s : %d] Send error : %s", IPString().c_str(), Port(), e.what());
            return -1;
        }
    }

    int16_t CUDPChannel::Read(char* buffer, int size) noexcept
    {
        assert(m_socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            auto read_bytes = m_socket.receive_from(boost::asio::buffer(buffer, size), m_remote_endpoint);
            if (error == boost::asio::error::eof)
            {
                LOG_INFO("udp-channel", "send error: [%s:%d] closed",
                    m_socket.remote_endpoint().address().to_string().c_str(),
                    m_socket.remote_endpoint().port());
                return 0;
            }
            return read_bytes;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("udp-channel", "[%s: %d] receive error : %s", IPString().c_str(), Port(), e.what());
            return -1;
        }
    }
}
