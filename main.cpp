
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
        : clientSocket_(io_service)
        , strand_(io_service)
        , parentSession_(session)
        , socketBuffer_(4096)
        , sshBuffer_(4096)
    {
        session_.optionsCopy(session);
    }

    ~IncomingConnection()
    {
        parentSession_.log(SSH_LOG_WARNING, "Terminating connection");

        clientSocket_.close();

        if (worker_.joinable())
            worker_.join();
    }

    boost::asio::ip::tcp::socket& socket()
    {
        return clientSocket_;
    }

    void start(short port, const std::string& password)
    {
        parentSession_.log(SSH_LOG_WARNING, "Starting connection to remote port: %d", port);

        try
        {
            session_.connect();
            int r = session_.userauthPassword(password.c_str());
            if (r != SSH_AUTH_SUCCESS)
                throw std::runtime_error("auth failed");

            channel_ = std::make_unique<ssh::Channel>(session_);
            channel_->openSession();

            const auto cmd = std::string("socat - TCP4:localhost:") + std::to_string(port);
            channel_->requestExec(cmd.c_str());

            worker_ = std::thread(std::bind(&IncomingConnection::worker, this));
        }
        catch (ssh::SshException& e)
        {
            std::cerr << "Failed to launch socat: " << e.getError() << std::endl;
        }
    }

private:

    void worker()
    {
        const auto instance(shared_from_this());

        while (clientSocket_.is_open())
            processSockets();
    }

    void readFromClient()
    {
        try
        {
            if (!clientSocket_.available())
                return; 

            auto bytes = clientSocket_.read_some(boost::asio::buffer(socketBuffer_));

            int written = 0;
            while (bytes)
            {
                const auto res = channel_->write(socketBuffer_.data() + written, bytes);
                written += res;
                bytes -= res;
            }
        }
        catch (ssh::SshException e)
        {
            std::cerr << "Failed to write to ssh: " << e.getError() << std::endl;
            clientSocket_.close();
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to read from client: " << e.what() << std::endl;
            clientSocket_.close();
        }

    }

    void readFromSsh()
    {
        try
        {
            const auto read = channel_->readNonblocking(sshBuffer_.data(), sshBuffer_.size());
            if (read)
                boost::asio::write(clientSocket_, boost::asio::buffer(sshBuffer_.data(), read), boost::asio::transfer_all());
        }
        catch (ssh::SshException e)
        {
            std::cerr << "Failed to read from ssh: " << e.getError() << std::endl;
            clientSocket_.close();
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to write to client: " << e.what() << std::endl;
            clientSocket_.close();
        }
    }

    void processSockets()
    {
        const int ssh = session_.getSocket();
        const int client = clientSocket_.native_handle();

        fd_set readset;

        timeval timeout = {};
        timeout.tv_usec = 100;

        FD_ZERO(&readset);
        FD_SET(ssh, &readset);
        FD_SET(client, &readset);

        int smax = max(ssh, client);

        int result = select(smax + 1, &readset, NULL, NULL, &timeout);
        if (result > 0)
        {
            if (FD_ISSET(ssh, &readset))
                readFromSsh();
            if (FD_ISSET(client, &readset))
                readFromClient();
        }
        else
        if (result < 0)
        {
            clientSocket_.close();
        }
    }

    boost::asio::ip::tcp::socket clientSocket_;
    ssh::Session& parentSession_;
    boost::asio::io_service::strand strand_;

    ssh::Session session_;
    std::unique_ptr<ssh::Channel> channel_;
    std::thread worker_;
    std::vector<char> socketBuffer_;
    std::vector<char> sshBuffer_;
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
        , password_(password)
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
            connection->start(port_, password_);

        start();
    }

private:
    boost::asio::ip::tcp::acceptor acceptor_;
    ssh::Session session_;
    const short port_;
    const std::string password_;
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

int main(int argc, const char **argv) 
{
    char buf[4096];
    DWORD username_len = sizeof(buf);
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

    strncpy(buf, userName.c_str(), sizeof(buf));
    ssh_getpass("Password: ", buf, sizeof(buf), 0, 0);

    std::string password = buf;
    
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
