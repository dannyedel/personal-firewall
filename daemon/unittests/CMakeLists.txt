include_directories(SYSTEM ..)

add_executable(boost_testrunner
	test_main
	test_rule
	test_rulerepository
	test_verdict
	../rule
	../rulerepository
	../packet
	../verdict
)

# Copy rule data
file(COPY rules DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY invalid-rules DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(boost_testrunner
	PRIVATE
		${Boost_LIBRARIES}
		pthread
)

add_test(NAME Boost_Test_Runner COMMAND boost_testrunner)
