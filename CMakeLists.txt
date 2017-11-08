cmake_minimum_required(VERSION 3.8)
project(forward-port)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(BOOST_COMPONENTS system	program_options	filesystem thread)

find_package(Boost COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
set(WITH_GCRYPT ON)
add_subdirectory("libssh")

include_directories(
	${BOOST_ROOT}
	${LIBSSH_PUBLIC_INCLUDE_DIRS}
	${CMAKE_BINARY_DIR}
)

add_subdirectory("file-sync")

set(SOURCE_FILES main.cpp)
add_executable(forward-port ${SOURCE_FILES})
target_link_libraries(forward-port ${LIBSSH_SHARED_LIBRARY} ${Boost_LIBRARIES})
