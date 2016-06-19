project(personal-firewall)
cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)

### OPTIONS ###

### END OPTIONS ###

# the daemon interactive with netfilter, running with
# elevated privileges
add_subdirectory(daemon)

# GUI, running as normal user
#add_subdirectory(gui)

# CLI, running as normal user
#add_subdirectory(cli)
