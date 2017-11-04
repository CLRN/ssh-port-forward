cmake_minimum_required(VERSION 3.8)
project(forward-port)

set(CMAKE_CXX_STANDARD 17)
if(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
endif(MSVC)
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(BOOST_ROOT "g:/git/boost_1_65_1")
set(ZLIB_ROOT "g:/git/zlib-1.2.3-bin")
set(ZLIB_LIBRARY "g:/git/zlib-1.2.3-bin/lib/zlibstat.lib")
set(OPENSSL_ROOT_DIR "g:/git/openssl-0.9.8h")

add_subdirectory("libssh")

include_directories(
	${BOOST_ROOT}
	${LIBSSH_PUBLIC_INCLUDE_DIRS}
	${CMAKE_BINARY_DIR}
)

link_directories(${BOOST_ROOT}/stage/lib)

add_definitions(
    -D__USE_W32_SOCKETS
    -D__WIN32__
    -D_WIN32_WINNT=0x0601
#	-DZLIB_WINAPI
#    -DBOOST_HAS_GETSYSTEMTIMEASFILETIME
#    -DBOOST_PLAT_WINDOWS_DESKTOP
)

set(SOURCE_FILES main.cpp)
add_executable(forward-port ${SOURCE_FILES})
target_link_libraries(forward-port ${LIBSSH_SHARED_LIBRARY})