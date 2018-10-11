#pragma once

#include <string>
#include <set>
#include <thread>
#include <boost/asio.hpp>
#include <mutex>
#include <condition_variable>

#include "pg_msg.h"
#include "pg_buffer.h"

namespace ICE {
    class CChannel {
    protected:
        using boost_tcp  = boost::asio::ip::tcp;
        using boost_udp  = boost::asio::ip::udp;
        using boost_addr = boost::asio::ip::address;

    public:
        CChannel(){};
        virtual ~CChannel() {};

        /// Get the local endpoint ip address as string
        /**
        *
        * @returns Returns null string if an error occurred.
        */
        virtual std::string IPString() const noexcept = 0;

        /// Get the local endpoint port
        /**
        * @returns Returns 0 if an error occurred.
        */
        virtual int Port() const noexcept  = 0;

        /// Get the local endpoint Protocol
        /**
        * @returns Returns 0 if an error occurred.
        */
        virtual int Protocol() const noexcept = 0;

    public:
        /// Bind the socket to the given local endpoint.
        /**
        * This function binds the socket to the specified endpoint on the local
        * machine.
        *
        * @param ip the local ip[ipv4 or ipv6] address try to bind
        *
        * @returns Returns false if an error occurred, otherwise returns true
        */
        virtual bool BindLocal(const std::string& ip, int port) noexcept = 0;

        /// Connect the socket to the specified endpoint.
        /**
        * This function is used to connect a socket to the specified remote endpoint.
        * The function call will block until the connection is successfully made or
        * an error occurs.
        *
        * The socket is automatically opened if it is not already open. If the
        * connect fails, and the socket was automatically opened, the socket is
        * not returned to the closed state.
        *
        * @param remote_ip The remote endpoint ip address[ipv4 or ipv6] to which the socket will be
        * connected.
        *
        * @returns Returns false if an error occurred, otherwise returns true
        */
        virtual bool BindRemote(const std::string& remote_ip, int port) noexcept = 0;

        /// Write some data to the socket.
        /**
        * This function is used to write data to the stream socket. The function call
        * will block until @size bytes of the data has been written
        * successfully, or until an error occurs.
        *
        * @param buffers to be written to the socket.
        *
        *
        * @returns Returns false if an error occurred, otherwise returns true
        *
        */
        virtual bool Write(const char* buffer, int size) noexcept = 0;

        /// Read some data from the peer endpoint.
        /**
        * This function is used to read data from the stream socket. The function
        * call will block until @size bytes of data has been read successfully,
        * or until an error occurs.
        *
        * @param buffers into which the data will be read.
        *
        * @param ec Set to indicate what error occurred, if any.
        *
        * @returns Returns false if an error occurred,otherwise returns true
        *
        */
        virtual bool Read(char* buffer, int size) noexcept = 0;

    protected:
        static boost::asio::io_service sIOService;
    };

    class CTCPChannel : public CChannel{
    public:
        CTCPChannel();
        virtual ~CTCPChannel();

    protected:
        explicit CTCPChannel(boost_tcp::socket socket);

    public:
        virtual std::string IPString() const noexcept;
        virtual int         Port()     const noexcept;
        int                 Protocol() const noexcept final;

    public:
        virtual bool BindLocal(const std::string& ip, int port) noexcept override;
        virtual bool BindRemote(const std::string& remote_ip, int port) noexcept override;
        virtual bool Write(const char* buffer, int size) noexcept override;
        virtual bool Read(char* buffer, int size) noexcept override;

    private:
        boost_tcp::socket m_socket;
    };

    /////////////////////// CUDPChannel /////////////////////
    class CUDPChannel : public CChannel{
    public:
        CUDPChannel();
        virtual ~CUDPChannel();

    public:
        virtual std::string IPString() const noexcept;
        virtual int         Port()     const noexcept;
        int                 Protocol() const noexcept override final;

    public:
        virtual bool BindLocal(const std::string& ip, int port) noexcept;
        virtual bool BindRemote(const std::string& remote_ip, int port) noexcept;
        virtual bool Write(const char* buffer, int size) noexcept;
        virtual bool Read(char* buffer, int size) noexcept;

    private:
        boost_udp::socket   m_socket;
        boost_udp::endpoint m_remote_endpoint;
    };

    class CAsyncTCPChannel : public CTCPChannel, PG::MsgEntity {
    public:
        enum Event{
            write = 0,
            read,
            connected,
        };

    public:
        CAsyncTCPChannel(const std::string& unique_name, int buffer_size = sDefaultSize);
        virtual ~CAsyncTCPChannel() {};

    public:
        virtual bool Write(const char* buffer, int size) noexcept { return true; }
        virtual bool Read(char *buffer, int size) noexcept { return true; }

    public:
        virtual bool OnRead(const char *buffer, int size) = 0;
        virtual bool OnWrite() = 0;

    private:
        PG::circular_buffer m_buffer;

    private:
        static const int sDefaultSize = 1024;
    };
}