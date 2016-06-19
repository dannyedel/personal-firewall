project(personal-firewall)
cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)

### OPTIONS ###

### END OPTIONS ###


### find libnetfilter-queue via pkg-config

include(FindPkgConfig)
pkg_search_module(NFQUEUE REQUIRED libnetfilter_queue)

set(persfw_sources
	main
)

add_definitions(-Wall -Wextra -Werror)

add_executable(personal-firewall
	${persfw_sources}
)

target_link_libraries(personal-firewall
	${NFQUEUE_LIBRARIES}
)

include_directories(SYSTEM ${NFQUEUE_INCLUDE_DIRS})

install(TARGETS
	personal-firewall
	RUNTIME DESTINATION bin
)
