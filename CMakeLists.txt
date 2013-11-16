# @author $username$ <$usermail$>
# @date $date$
# snmp-agent cmake build script

cmake_minimum_required(VERSION 2.6.4)

########################################################################
# options

option(WITH_TESTS "Build tests."  OFF)
option(WITH_DOCS  "Generate docs" OFF)

########################################################################
# general

project(snmp-agent)

set(snmp-agent_VERSION_MAJOR 0)
set(snmp-agent_VERSION_MINOR 0)
set(snmp-agent_VERSION_PATCH 0)
# configuration header
configure_file(
	"${PROJECT_SOURCE_DIR}/src/snmp-agent_config.cfg"
	"${PROJECT_SOURCE_DIR}/src/snmp-agent_config.h"
	ESCAPE_QUOTES
)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}"
                      "${PROJECT_SOURCE_DIR}/cmake/Modules")

include_directories("${PROJECT_SOURCE_DIR}/src")
add_definitions("-DSTDCXX_98_HEADERS -D_SNMPv3")

########################################################################
# threads

list(APPEND LIBRARIES pthread rt crypto ssl)

########################################################################
# agent++

set(AGENTXX_USE_STATIC_LIBS ON)
find_package(AgentXX REQUIRED)
include_directories(${AGENTXX_INCLUDE_DIR})
list(APPEND LIBRARIES ${AGENTXX_LIBRARIES})

########################################################################
# snmp++

set(SNMPXX_USE_STATIC_LIBS ON)
find_package(SnmpXX REQUIRED)
include_directories(${SNMPXX_INCLUDE_DIR})
list(APPEND LIBRARIES ${SNMPXX_LIBRARIES})

########################################################################
# docs

set(SRC
	./src/JasperNetFlowSNMPReporter.h
	./src/JasperNetFlowSNMPReporter.cpp
	./src/snmp-agent_config.cfg
	./src/snmp-agent.cpp
)

add_executable(snmp-agent ${SRC})
target_link_libraries(snmp-agent ${LIBRARIES})


########################################################################
# docs

if(WITH_DOCS)
	FIND_PACKAGE(Doxygen)
	if(DOXYGEN_FOUND)
		set(ENV{snmp-agent_ROOT} "${PROJECT_SOURCE_DIR}")
		ADD_CUSTOM_TARGET(doc COMMAND ${CMAKE_COMMAND}
			-D PDIR="${PROJECT_SOURCE_DIR}"
			-P "${PROJECT_SOURCE_DIR}/doc/doxygen.cmake")
	else()
		message(WARNING
			"Doxygen not found."
			" Documentation wouldn't be ganarated")
	endif()
endif()

########################################################################
# tests

function(nx_GTEST_ADD_TESTS executable extra_args)
	foreach(source ${ARGN})
		file(READ "${source}" contents)
		string(REGEX MATCHALL "TEST_?F?\\(([A-Za-z_0-9 ,]+)\\)"
			found_tests ${contents})
		foreach(hit ${found_tests})
			string(REGEX REPLACE ".*\\( *([A-Za-z_0-9]+),"
			                     " *([A-Za-z_0-9]+) *\\).*"
			                     "\\1.\\2"
			                     test_name ${hit})
			add_test("${executable}-${test_name}"
				${executable}
				--gtest_filter=${test_name}
				${extra_args})
		endforeach()
	endforeach()
endfunction()

if(WITH_TESTS)
	set(SOURCES_TEST
		./test/test.cpp)
	enable_testing()
	find_package(GTest REQUIRED)
	include_directories(${GTEST_INCLUDE_DIRS})
	set(TEST test_${PROJECT_NAME})
	add_executable(${TEST} ${SOURCES_TEST})
	if(NOT WIN32)
		SET_TARGET_PROPERTIES(${TEST} 
			PROPERTIES LINK_FLAGS -pthread)
	endif(NOT WIN32)
	target_link_libraries("${TEST}" ${GTEST_LIBRARIES} ${LIBRARIES})
	nx_GTEST_ADD_TESTS("${TEST}" ${SOURCES_TEST})
endif()

########################################################################
# installation

set(CPACK_SET_DESTDIR ON)

install(TARGETS ${TARGETS} DESTINATION bin)
#install(FILES <files> DESTINATION <dest>)

INCLUDE(InstallRequiredSystemLibraries)

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "snmp-agent DESC")
SET(CPACK_PACKAGE_VENDOR "ORG")
SET(CPACK_PACKAGE_DESCRIPTION_FILE
	"${CMAKE_CURRENT_SOURCE_DIR}/README.markdown")
SET(CPACK_RESOURCE_FILE_LICENSE
	"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
SET(CPACK_PACKAGE_VERSION_MAJOR ${snmp-agent_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${snmp-agent_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${snmp-agent_VERSION_PATCH})
SET(CPACK_PACKAGE_INSTALL_DIRECTORY
	"CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
IF(WIN32 AND NOT UNIX)
	# NOT IMPLEMENTED
ELSE(WIN32 AND NOT UNIX)
	SET(CPACK_STRIP_FILES ${TARGETS})
	SET(CPACK_SOURCE_STRIP_FILES "")
ENDIF(WIN32 AND NOT UNIX)
#SET(CPACK_PACKAGE_EXECUTABLES "null" "null desc")

INCLUDE(CPack)

