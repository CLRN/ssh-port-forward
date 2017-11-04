#include <iostream>

#include <boost/shared_ptr.hpp>
#include <boost/process.hpp>
#include <boost/asio/io_service.hpp>

int main()
{
    boost::asio::io_service ios;
    std::vector<char> buf;

    bp::async_pipe ap(ios);

    bp::child c(bp::search_path("g++"), "main.cpp", bp::std_out > ap);

    boost::asio::async_read(ap, boost::asio::buffer(buf),
                    [](const boost::system::error_code &ec, std::size_t size){});

    ios.run();
    c.wait();
    int result = c.exit_code();

    return 0;
}