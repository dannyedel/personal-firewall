### find libnetfilter-queue via pkg-config

include(FindPkgConfig)
pkg_search_module(NFQUEUE REQUIRED libnetfilter_queue)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS iostreams log)
add_definitions(-DBOOST_ALL_DYN_LINK)

set(persfw_sources
	main
	netfilter-callback
	dissect-packet
	verdict
	packet
)

add_definitions(-Wall -Wextra -Werror)

add_executable(personal-firewalld
	${persfw_sources}
)

target_link_libraries(personal-firewalld
	PRIVATE
		${NFQUEUE_LIBRARIES}
		${Boost_LIBRARIES}
		${Thread_LIBRARIES}
)

include_directories(SYSTEM ${NFQUEUE_INCLUDE_DIRS})

install(TARGETS
	personal-firewalld
	RUNTIME DESTINATION sbin
)
