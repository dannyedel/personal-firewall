include_directories(SYSTEM ..)

find_package(Boost REQUIRED
	COMPONENTS
		unit_test_framework
		system
		log
)

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

add_executable(boost_testrunner
	test_main
	test_rule
	test_rulerepository
	../rule
	../rulerepository
	../packet
	../verdict
)

target_link_libraries(boost_testrunner PRIVATE ${Boost_LIBRARIES})

add_test(NAME Boost_Test_Runner COMMAND boost_testrunner)
