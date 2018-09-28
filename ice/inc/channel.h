#pragma once

#include <string>
#include <set>
#include <thread>
#include <boost/asio.hpp>
#include <mutex>
#include <condition_variable>

namespace ICE {
    class CChannel {
    protected:
        using boost_tcp  = boost::asio::ip::tcp;
        using boost_udp  = boost::asio::ip::udp;
        using boost_addr = boost::asio::ip::address;

    public:
        CChannel() {};
        virtual ~CChannel() {};

        /// Get the local endpoint ip address as string
        /**
        *
        * @returns Returns null string if an error occurred.
        */
        virtual std::string GetIPString()const noexcept  = 0;

        /// Get the local endpoint port
        /**
        * @returns Returns 0 if an error occurred.
        */
        virtual int         GetPort()    const noexcept  = 0;

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
        boost::asio::io_service m_io_service;
    };

    class CTCPChannel : public CChannel{
    public:
        CTCPChannel();
        virtual ~CTCPChannel();

    public:
        virtual std::string GetIPString()const noexcept;
        virtual int         GetPort()    const noexcept;

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
        virtual bool BindLocal(const std::string& ip, int port) noexcept;

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
        virtual bool BindRemote(const std::string& remote_ip, int port) noexcept;

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
        virtual bool Write(const char* buffer, int size) noexcept;

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
        virtual bool Read(char* buffer, int size) noexcept;

    protected:
        boost_tcp::socket   m_socket;
    };

    /////////////////////// CTCPServerChannel /////////////////////
    class CTCPServerChannel : public CTCPChannel {
    protected:
        class Client {
        public:
            Client(boost_tcp::socket* socket = nullptr) :
                m_socket(socket)
            {
            }

            virtual ~Client() 
            {
                if (m_socket)
                    delete m_socket;
                m_socket = nullptr;
            }

        protected:
            boost_tcp::socket* m_socket;
        };

        using ClientContainer = std::set<Client*>;

    public:
        CTCPServerChannel(int backlog, int max_client) : 
            CTCPChannel(), m_acceptor(m_io_service), 
            m_backlog(backlog), m_max_client(max_client)
        {
        }
        virtual ~CTCPServerChannel();

    protected:
        bool AddClient(boost_tcp::socket *client_socket);
        bool ReleaseClient(boost_tcp::socket *client_socket);

    protected:
        static void AcceptThread (CTCPServerChannel *pInstance);
        static void ReceiveThread(CTCPServerChannel *pInstance);

    private:
        std::mutex              m_clients_mutex;
        std::condition_variable m_clients_condition;
        ClientContainer         m_clients;
        boost_tcp::acceptor     m_acceptor;
        const int               m_backlog;
        const int               m_max_client;
    };

    /////////////////////// CUDPChannel /////////////////////
    class CUDPChannel : public CChannel {
    public:
        CUDPChannel();
        virtual ~CUDPChannel();

    public:
        virtual std::string GetIPString()const noexcept;
        virtual int         GetPort()    const noexcept;

    public:
        virtual bool BindLocal(const std::string& ip, int port) noexcept;
        virtual bool BindRemote(const std::string& remote_ip, int port) noexcept;
        virtual bool Write(const char* buffer, int size) noexcept;
        virtual bool Read(char* buffer, int size) noexcept;

    protected:
        boost_udp::socket   m_socket;
        boost_udp::endpoint m_remote_endpoint;
    };
}