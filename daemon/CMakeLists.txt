### find libnetfilter-queue via pkg-config

include(FindPkgConfig)
pkg_search_module(NFQUEUE REQUIRED libnetfilter_queue)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED
	COMPONENTS
		iostreams
		log
		system
		filesystem
		unit_test_framework
	)
add_definitions(-DBOOST_ALL_DYN_LINK)

set(persfw_sources
	netfilter-callback
	dissect-packet
	verdict
	packet
	rulerepository
	rule
)

add_definitions(-Wall -Wextra -Werror)

add_executable(personal-firewalld
	${persfw_sources}
	main
)

target_link_libraries(personal-firewalld
	PRIVATE
		${NFQUEUE_LIBRARIES}
		${Boost_LIBRARIES}
		pthread
)

### FIXME: Make these better visible to the user

if(NOT SERVICE_DEFAULT_VERDICT)
	set(SERVICE_DEFAULT_VERDICT reject)
endif()

if(NOT SERVICE_RULE_DIRECTORY)
	set(SERVICE_RULE_DIRECTORY
		"${CMAKE_PREFIX_PATH}/etc/personal-firewalld/rules")
endif()

configure_file(
	systemd/personal-firewalld.service.in
	systemd/personal-firewalld.service
	NEWLINE_STYLE UNIX
)

include_directories(SYSTEM ${NFQUEUE_INCLUDE_DIRS})

install(TARGETS
	personal-firewalld
	RUNTIME DESTINATION sbin
)

install(FILES
	${CMAKE_CURRENT_BINARY_DIR}/systemd/personal-firewalld.service
	DESTINATION /etc/systemd/system/
)

add_subdirectory(unittests)
