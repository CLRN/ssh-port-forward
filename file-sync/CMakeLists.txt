add_subdirectory("dir_monitor")

set(SOURCE_FILES main.cpp)
add_executable(file-sync ${SOURCE_FILES})
target_link_libraries(file-sync ${LIBSSH_SHARED_LIBRARY} ${Boost_LIBRARIES} dir_monitor)
