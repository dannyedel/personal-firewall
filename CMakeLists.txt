project(personal-firewall)
cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

### OPTIONS ###

### END OPTIONS ###

add_definitions(-std=c++14)

# the daemon interactive with netfilter, running with
# elevated privileges
add_subdirectory(daemon)

# GUI, running as normal user
#add_subdirectory(gui)

# CLI, running as normal user
#add_subdirectory(cli)
