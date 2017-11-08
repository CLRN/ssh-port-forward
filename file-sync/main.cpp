
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <functional>

#include <libssh/libsshpp.hpp>
#include <libssh/callbacks.h>

#include <dir_monitor/dir_monitor.hpp>

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/make_shared.hpp>
#include <boost/program_options.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/algorithm/string.hpp>

namespace po = boost::program_options;

class RemoteFile
{
public:
    RemoteFile(ssh::Session& session, const std::string& root)
        : session_()
        , file_()
    {
        session_ = ssh_scp_new(session.getCSession(), SSH_SCP_WRITE, root.c_str());
        if (!session_)
            throw std::runtime_error("failed to open scp session");

        if (ssh_scp_init(session_) == SSH_ERROR)
            throw std::runtime_error("failed to initialize scp session");
    }

    ~RemoteFile()
    {
        if (session_)
            ssh_scp_free(session_);
    }

    void create(const boost::filesystem::path& local, const std::string& relative)
    {
        const auto perms = boost::filesystem::status(local).permissions();

        file_ = ssh_scp_push_file(session_, relative.c_str(), boost::filesystem::file_size(local), perms);
        if (file_ == SSH_ERROR)
            throw std::runtime_error("failed to push file");
    }

    void write(const std::vector<char>& buffer)
    {
        const auto res = ssh_scp_write(session_, buffer.data(), buffer.size());
        if (res == SSH_ERROR)
            throw std::runtime_error("failed to write file");
    }

private:
    ssh_scp session_;
    int file_;
};

void read(const boost::filesystem::path& path, std::vector<char>& buffer)
{
    boost::filesystem::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
        throw std::runtime_error("unable to open file for read");

    buffer.resize(boost::filesystem::file_size(path));
    std::copy(std::istream_iterator<char>(ifs), std::istream_iterator<char>(), buffer.begin());
}


int main(int argc, const char **argv) 
{
    ssh::Session session;

    try
    {
        // Declare the supported options.
        po::options_description desc("Allowed options");
        desc.add_options()
                ("help", "produce help message")
                ("windows-dir,W", po::value<std::string>()->default_value(""), "windows folder - source")
                ("linux-dir,L", po::value<std::string>()->default_value("~/"), "linux folder - target")
                ("host,H", po::value<std::string>()->default_value("vps"), "ssh server address")
                ("user,U", po::value<std::string>()->default_value("root"), "ssh user name")
                ("port,P", po::value<short>()->default_value(22), "ssh server port")
                ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help") || vm.empty())
        {
            std::cout << desc << std::endl;
            return 1;
        }

        const std::string userName = vm["user"].as<std::string>();

        char buf[4096] = {};
        strncpy(buf, userName.c_str(), sizeof(buf));
        ssh_getpass("Password: ", buf, sizeof(buf), 0, 0);

        std::string password = buf;

        session.setOption(SSH_OPTIONS_HOST, vm["host"].as<std::string>().c_str());
        session.setOption(SSH_OPTIONS_USER, userName.c_str());
        session.setOption(SSH_OPTIONS_PORT, vm["port"].as<short>());

        session.connect();
        int r = session.userauthPassword(password.c_str());
        if (r != SSH_AUTH_SUCCESS)
            throw std::runtime_error("auth failed");

        boost::asio::io_service svc;
        boost::asio::dir_monitor monitor(svc);

        boost::asio::signal_set signals(svc, SIGINT, SIGTERM);
        signals.async_wait(std::bind(&boost::asio::io_service::stop, &svc));

        const auto dir = boost::filesystem::absolute(vm["windows-dir"].as<std::string>());
        monitor.add_directory(vm["windows-dir"].as<std::string>());

        std::vector<char> buffer(4096);

        while (!svc.stopped())
        {
            const auto event = monitor.monitor();
            const auto local = boost::filesystem::absolute(event.path);

            boost::system::error_code e;
            const auto time = boost::filesystem::last_write_time(event.path, e);
            std::cout << event.type_cstr() << ":" << event.path.string() << ":" << time << std::endl;

            std::string relative = local.string();
            boost::algorithm::erase_all(relative, dir.string() + "/");

            RemoteFile file(session, vm["linux-dir"].as<std::string>());

            switch (event.type)
            {
                case boost::asio::dir_monitor_event::added:
                    file.create(event.path, relative);
                    break;
                case boost::asio::dir_monitor_event::removed:
                    break;
                case boost::asio::dir_monitor_event::modified:
                    read(event.path, buffer);

                    file.create(event.path, relative);
                    file.write(buffer);
                    break;
                case boost::asio::dir_monitor_event::renamed_old_name:
                    break;
                case boost::asio::dir_monitor_event::renamed_new_name:
                    break;
            }
        }

    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << ", ssh error: " << ssh_get_error(session.getCSession()) << std::endl;
    }
    return 0;
}
