#pragma once

#include <string>
#include <boost/asio.hpp>
#include <type_traits>

namespace ICE {
    class Channel {
    public:
        Channel() {}
        virtual ~Channel() = 0 {};

    public:
        template<class socket_type, class endpoint_type>
        bool BindSocket(socket_type &socket, const endpoint_type &ep) noexcept
        {
            static_assert(!std::is_pointer<socket_type>::value && !std::is_pointer<endpoint_type>::value, 
                "socket_type and endpoint_type cannot be pointer");
            try
            {
                socket.open(ep.protocol());
                socket.bind(ep);
                return true;
            }
            catch (const boost::system::system_error&)
            {
                return false;
            }
        }

    public:
        virtual bool Bind(const std::string& ip, int16_t port) noexcept = 0;
        virtual int16_t Write(const uint8_t* buffer, int size) noexcept = 0;
        virtual int16_t Read(uint8_t* buffer, int size) noexcept = 0;

    protected:
        static boost::asio::io_service sIOService;
    };

    class UDPChannel : public Channel {
    public:
        UDPChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~UDPChannel();

    public:
        bool BindRemote(const std::string &ip, int16_t port) noexcept;
        boost::asio::ip::udp::socket& Socket() { return m_Socket; }

    public:
        virtual bool Bind(const std::string& ip, int16_t port) noexcept override;
        virtual int16_t Write(const uint8_t* buffer, int size) noexcept override;
        virtual int16_t Read(uint8_t* buffer, int size) noexcept override;

    private:
        boost::asio::ip::udp::socket    m_Socket;
        boost::asio::ip::udp::endpoint  m_RemoteEp;
    };

    class TCPChannel : public Channel {
    public:
        TCPChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~TCPChannel();

    public:
        boost::asio::ip::tcp::socket& Socket() { return m_Socket; }

    public:
        virtual bool Bind(const std::string& ip, int16_t port) noexcept override;
        virtual int16_t Write(const uint8_t* buffer, int size) noexcept override final;
        virtual int16_t Read(uint8_t* buffer, int size) noexcept override final;

    protected:
        boost::asio::ip::tcp::socket m_Socket;
    };

    class TCPActiveChannel : public TCPChannel {
    public:
        TCPActiveChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~TCPActiveChannel();

    public:
        bool Connect(const boost::asio::ip::tcp::endpoint& ep) noexcept;
        bool Connect(const std::string& ip, int16_t port) noexcept;

    };

    class TCPPassiveChannel : public TCPChannel {
    public:
        TCPPassiveChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~TCPPassiveChannel();

    public:
        virtual bool Bind(const std::string& ip, int16_t port) noexcept override final;

    public:
        bool Accept(boost::asio::ip::tcp::socket& socket, boost::asio::ip::tcp::endpoint &ep) noexcept;
        bool Accept(boost::asio::ip::tcp::socket& socket, const std::string& ip, int16_t port) noexcept;

    private:
        boost::asio::ip::tcp::acceptor m_Acceptor;
    };
}