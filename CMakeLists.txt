cmake_minimum_required(VERSION 3.8)
project(forward-port)

#set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(BOOST_ROOT "g:/git/boost_1_65_1")
include_directories(
    ${BOOST_ROOT}
)

add_definitions(
    -D__USE_W32_SOCKETS
    -D__WIN32__
    -D_WIN32_WINNT=0x0601
#    -DBOOST_HAS_GETSYSTEMTIMEASFILETIME
#    -DBOOST_PLAT_WINDOWS_DESKTOP
)

set(SOURCE_FILES main.cpp)
add_executable(forward-port ${SOURCE_FILES})