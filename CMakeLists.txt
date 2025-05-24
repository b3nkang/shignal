cmake_minimum_required(VERSION 3.10)

# project details
project(AuthApp VERSION 1.0)
set(USER_EXEC_NAME auth_user)
set(SERVER_EXEC_NAME auth_server)
set(SHIGNAL_EXEC_NAME shignal_server)
set(LIBRARY_NAME auth_app_lib)
set(LIBRARY_NAME_SHARED auth_app_lib_shared)

# turn on gdb
set(CMAKE_BUILD_TYPE Debug)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
include(CTest)
include(Warnings)
include(Curses)
include(Sqlite3)

# add shared libraries
set(SOURCES_SHARED
  src-shared/config.cxx
  src-shared/messages.cxx
  src-shared/logger.cxx
  src-shared/util.cxx
  src-shared/keyloaders.cxx)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE sqlite3)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})

# add student libraries
set(SOURCES
  src/pkg/server.cxx
  src/pkg/shignalServer.cxx
  src/pkg/user.cxx
  src/drivers/cli_driver.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/db_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/repl_driver.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})

# add user executable
add_executable(${USER_EXEC_NAME} src/cmd/user.cxx)
target_link_libraries(${USER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# add server executable
add_executable(${SERVER_EXEC_NAME} src/cmd/server.cxx)
target_link_libraries(${SERVER_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# Add signal server executable
add_executable(${SHIGNAL_EXEC_NAME} src/cmd/shignalServer.cxx)
target_link_libraries(${SHIGNAL_EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME}
  ${USER_EXEC_NAME}
  ${SERVER_EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 20
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS YES
)
