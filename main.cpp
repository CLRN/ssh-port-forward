
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <functional>

#include <libssh/libsshpp.hpp>
#include <libssh/callbacks.h>

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
#include <boost/weak_ptr.hpp>
#include <boost/program_options.hpp>

#include <windows.h>
#include <Lmcons.h>

ssh_threads_callbacks_struct g_Callbacks;

namespace po = boost::program_options;

class IncomingConnection : public boost::enable_shared_from_this<IncomingConnection>
{
public:
    typedef boost::shared_ptr<IncomingConnection> Ptr;

    IncomingConnection(boost::asio::io_service& io_service, 
                       ssh::Session& session)
        : socket_(io_service)
        , channel_(session)
        , socketBuffer_(4096)
    {
    }

    ~IncomingConnection()
    {
        channel_.getSession().log(SSH_LOG_WARNING, "Terminating connection");

        socket_.close();

        if (sshReader_.joinable())
            sshReader_.join();
    }

    boost::asio::ip::tcp::socket& socket()
    {
        return socket_;
    }

    void start(short port)
    {
        channel_.getSession().log(SSH_LOG_WARNING, "Starting connection to remote port: %d", port);

        try
        {
            channel_.openSession();

            const auto cmd = std::string("socat - TCP4:localhost:") + std::to_string(port);
            channel_.requestExec(cmd.c_str());
        }
        catch (ssh::SshException& e)
        {
            std::cerr << "Failed to launch socat: " << e.getError() << std::endl;
        }

        sshReader_ = std::thread(std::bind(&IncomingConnection::sshReader, this));
        startSocketRead();
    }

private:

    void startSocketRead()
    {
        const auto instance(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(socketBuffer_), [instance, this](boost::system::error_code e, std::size_t bytes)
        {
            if (e)
            {
                socket_.close();
                return;
            }

            int written = 0;
            while (bytes)
            {
                const auto res = channel_.write(socketBuffer_.data() + written, bytes);
                written += res;
                bytes -= res;
            }

            startSocketRead();
        });
    }

    void sshReader()
    {
        std::vector<char> buffer;

        for (; socket_.is_open();)
        {
            try
            {
                const auto bytes = channel_.poll();
                if (!bytes)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }

                buffer.resize(bytes);
                const auto read = channel_.read(buffer.data(), buffer.size());

                boost::asio::write(socket_, boost::asio::buffer(buffer), boost::asio::transfer_all());
            }
            catch (const std::exception& e)
            {
                std::cerr << "Exception in read thread: " << e.what() << std::endl;
                socket_.close();
            }
        }
    }

    boost::asio::ip::tcp::socket socket_;
    ssh::Channel channel_;
    std::thread sshReader_;
    std::vector<char> socketBuffer_;
};


class Server : public boost::enable_shared_from_this<Server>
{
public:
    Server(boost::asio::io_service& svc,
           short listeningPort,
           const std::string& host, 
           const std::string& user,
           const std::string& password,
           short sshServerPort,
           short forwardToPort) 
        : acceptor_(svc, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), listeningPort))
        , port_(forwardToPort)
    {
        session_.setOption(SSH_OPTIONS_HOST, host.c_str());
        session_.setOption(SSH_OPTIONS_USER, user.c_str());
        session_.setOption(SSH_OPTIONS_PORT, sshServerPort);

        session_.connect();
        int r = session_.userauthPassword(password.c_str());
        if (r != SSH_AUTH_SUCCESS)
            throw std::runtime_error("auth failed");
    }

    void start()
    {
        const auto connection = boost::make_shared<IncomingConnection>(acceptor_.get_io_service(), session_);
        const boost::weak_ptr<Server> weak(shared_from_this());

        acceptor_.async_accept(connection->socket(),
            [weak, connection, this](boost::system::error_code e)
        {
            if (const auto locked = weak.lock())
                handleAccept(connection, e);
        });
    }

    void handleAccept(IncomingConnection::Ptr connection, const boost::system::error_code& error)
    {
        if (!error)
            connection->start(port_);

        start();
    }

private:
    boost::asio::ip::tcp::acceptor acceptor_;
    ssh::Session session_;
    const short port_;
};


void init(bool debug)
{
    if (debug)
        ssh_set_log_level(SSH_LOG_FUNCTIONS);
    else
        ssh_set_log_level(SSH_LOG_WARNING);

    g_Callbacks.mutex_init = [](void** m) { *m = new std::mutex();                       return 0; };
    g_Callbacks.mutex_destroy = [](void** m) { delete reinterpret_cast<std::mutex*>(*m);    return 0; };
    g_Callbacks.mutex_lock = [](void** m) { reinterpret_cast<std::mutex*>(*m)->lock();   return 0; };
    g_Callbacks.mutex_unlock = [](void** m) { reinterpret_cast<std::mutex*>(*m)->unlock(); return 0; };
    g_Callbacks.thread_id = []() { return static_cast<unsigned long>(std::hash<std::thread::id>()(std::this_thread::get_id())); };

    ssh_threads_set_callbacks(&g_Callbacks);
    ssh_init();
}

void setStdInEcho(bool enable = true)
{
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode);
}

int main(int argc, const char **argv) 
{
    char buf[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(buf, &username_len);

    std::string userName(buf);

    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("host,H", po::value<std::string>()->default_value("localhost"), "ssh server address")
        ("user,U", po::value<std::string>()->default_value(userName), "ssh user name")
        ("srv-port", po::value<short>()->default_value(22), "ssh server port")
        ("port,P", po::value<short>()->default_value(22), "target port on remote machine to forward to")
        ("listen,L", po::value<short>()->default_value(22), "listening port on this machine")
        ("debug", po::bool_switch()->default_value(false), "enable debug logging")
        ;
    
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") || vm.empty())
    {
        std::cout << desc << std::endl;
        return 1;
    }

    userName = vm["user"].as<std::string>();

    std::cout << "Enter password for [" << userName << "]:" << std::endl;

    std::string password;

    setStdInEcho(false);
    std::cin >> password;
    setStdInEcho(true);
    
    try 
    {
        init(vm["debug"].as<bool>());
        
        boost::asio::io_service svc;
        const auto server = boost::make_shared<Server>(
            svc,
            vm["listen"].as<short>(),
            vm["host"].as<std::string>(),
            userName,
            password,
            vm["srv-port"].as<short>(),
            vm["port"].as<short>());

        std::string().swap(password);

        server->start();

        std::cout << "Waiting for incoming connection on localhost:" << vm["listen"].as<short>() << std::endl;
        svc.run();
    }
    catch (ssh::SshException e) 
    {
        std::cerr << "Error during connection: " << e.getError() << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to start server: " << e.what() << std::endl;
    }
    return 0;
}
