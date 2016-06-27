### find libnetfilter-queue via pkg-config

include(FindPkgConfig)
pkg_search_module(NFQUEUE REQUIRED libnetfilter_queue)

set(persfw_sources
	main
)

add_definitions(-Wall -Wextra -Werror)

add_executable(personal-firewalld
	${persfw_sources}
)

target_link_libraries(personal-firewalld
	PRIVATE
		${NFQUEUE_LIBRARIES}
)

include_directories(SYSTEM ${NFQUEUE_INCLUDE_DIRS})

install(TARGETS
	personal-firewalld
	RUNTIME DESTINATION sbin
)
