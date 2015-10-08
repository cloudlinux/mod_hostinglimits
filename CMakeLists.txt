CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(HOSTINGLIMITS)

SET(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

### For RPM Build ##########################################################################################################################
IF (DEFINED BUILD)


# Search for Apache and determine versions and paths
FIND_PACKAGE(ApacheForBuild REQUIRED)




# --- Apache 2.2 ---------------------------------------------------------------------------------------------------------------------------
IF (APACHE2_2_FOUND)

MESSAGE (STATUS "****** Apache2.2: ${APACHE2_2_HTTPD_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache2.2: ${APACHE2_2_APR_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache2.2: ${APACHE2_2_APRUTIL_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache2.2: ${APACHE2_2_HTTPD_MODULES}")

#INCLUDE_DIRECTORIES(${APACHE2_2_HTTPD_INCLUDE_DIR})
#INCLUDE_DIRECTORIES(${APACHE2_2_APR_INCLUDE_DIR})
#INCLUDE_DIRECTORIES(${APACHE2_2_APRUTIL_INCLUDE_DIR})

# Set path to C-source for specific Apache version
SET(mod_hostinglimits_SRCS src/apache2.x/mod_hostinglimits.c)

# Set C-source compilation flags and properties (for Linux)
SET_SOURCE_FILES_PROPERTIES(${mod_hostinglimits_SRCS} PROPERTIES COMPILE_FLAGS "-DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE")

# This code eliminates error message of cmake...
if(COMMAND cmake_policy)
     cmake_policy(SET CMP0003 NEW)
#     cmake_policy(SET CMP0002 NEW)
endif(COMMAND cmake_policy)

# Set target module properties
ADD_LIBRARY(mod_hostinglimits_2_2 MODULE ${mod_hostinglimits_SRCS})
SET_TARGET_PROPERTIES(mod_hostinglimits_2_2 PROPERTIES PREFIX "" SUFFIX ".so"
                         OUTPUT_NAME "mod_hostinglimits" LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib2.2"
                         COMPILE_FLAGS "-I${APACHE2_2_HTTPD_INCLUDE_DIR} -I${APACHE2_2_APR_INCLUDE_DIR} -I${APACHE2_2_APRUTIL_INCLUDE_DIR}")

TARGET_LINK_LIBRARIES(mod_hostinglimits_2_2 ${APACHE2_2_APR_LIBRARY})

ADD_DEFINITIONS(-DAPACHE2_2)

install(TARGETS mod_hostinglimits_2_2
	DESTINATION ${APACHE2_2_HTTPD_MODULES}
	COMPONENT Runtime
	)

ENDIF (APACHE2_2_FOUND)




# --- Apache 2.0 ---------------------------------------------------------------------------------------------------------------------------
IF (APACHE2_0_FOUND)

MESSAGE (STATUS "****** Apache2.0: ${APACHE2_0_HTTPD_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache2.0: ${APACHE2_0_APR_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache2.0: ${APACHE2_0_APRUTIL_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache2.0: ${APACHE2_0_HTTPD_MODULES}")

#INCLUDE_DIRECTORIES(${APACHE2_0_HTTPD_INCLUDE_DIR})
#INCLUDE_DIRECTORIES(${APACHE2_0_APR_INCLUDE_DIR})
#INCLUDE_DIRECTORIES(${APACHE2_0_APRUTIL_INCLUDE_DIR})

# Set path to C-source for specific Apache version
SET(mod_hostinglimits_SRCS src/apache2.x/mod_hostinglimits.c)

# Set C-source compilation flags and properties (for Linux)
SET_SOURCE_FILES_PROPERTIES(${mod_hostinglimits_SRCS} PROPERTIES COMPILE_FLAGS "-DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE")

# This code eliminates error message of cmake...
if(COMMAND cmake_policy)
     cmake_policy(SET CMP0003 NEW)
#     cmake_policy(SET CMP0002 NEW)
endif(COMMAND cmake_policy)

# Set target module properties
ADD_LIBRARY(mod_hostinglimits_2_0 MODULE ${mod_hostinglimits_SRCS})
SET_TARGET_PROPERTIES(mod_hostinglimits_2_0 PROPERTIES PREFIX "" SUFFIX ".so" OUTPUT_NAME "mod_hostinglimits"
                         LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib2.2h"
                         COMPILE_FLAGS "-I${APACHE2_0_HTTPD_INCLUDE_DIR} -I${APACHE2_0_APR_INCLUDE_DIR} -I${APACHE2_0_APRUTIL_INCLUDE_DIR}")

TARGET_LINK_LIBRARIES(mod_hostinglimits_2_0 ${APACHE2_0_APR_LIBRARY})

ADD_DEFINITIONS(-DAPACHE2_2)

install(TARGETS mod_hostinglimits_2_0
	DESTINATION ${APACHE2_0_HTTPD_MODULES}
	COMPONENT Runtime
	)

ENDIF (APACHE2_0_FOUND)




# --- Apache 1.3 ---------------------------------------------------------------------------------------------------------------------------
IF (APACHE1_3_FOUND)

# Directive to link with liblve
LINK_LIBRARIES(lve)

MESSAGE (STATUS "****** Apache1.3: ${HTTPD_INCLUDE_DIR}")
MESSAGE (STATUS "****** Apache1.3: ${HTTPD_MODULES}")

#INCLUDE_DIRECTORIES(${HTTPD_INCLUDE_DIR})

# Set path to C-source for specific Apache version
  SET(mod_hostinglimits_SRCS
	src/apache1.3/mod_hostinglimits.c
  )

# Set C-source compilation flags and properties (for Linux)
SET_SOURCE_FILES_PROPERTIES(${mod_hostinglimits_SRCS} PROPERTIES COMPILE_FLAGS "-DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE")

# This code eliminates error message of cmake...
if(COMMAND cmake_policy)
     cmake_policy(SET CMP0003 NEW)
#     cmake_policy(SET CMP0002 NEW)
endif(COMMAND cmake_policy)

# Set target module properties
ADD_LIBRARY(mod_hostinglimits_1_3 MODULE ${mod_hostinglimits_SRCS})
SET_TARGET_PROPERTIES(mod_hostinglimits_1_3 PROPERTIES PREFIX "" SUFFIX ".so" OUTPUT_NAME "mod_hostinglimits"
                         LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib1.3"
                         COMPILE_FLAGS "-I${HTTPD_INCLUDE_DIR}")

TARGET_LINK_LIBRARIES(mod_hostinglimits_1_3)
ADD_DEFINITIONS(-DEAPI)
ADD_DEFINITIONS(-DAPACHE1_3)

install(TARGETS mod_hostinglimits_1_3
	DESTINATION ${HTTPD_MODULES}
	COMPONENT Runtime
	)

ENDIF (APACHE1_3_FOUND)




### For CPanel (not for RPM build) #########################################################################################################
ELSE (DEFINED BUILD)

# Search for Apache and determine version and paths
FIND_PACKAGE(ApacheForCPanel REQUIRED)

INCLUDE_DIRECTORIES(${HTTPD_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${APR_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${APRUTIL_INCLUDE_DIR})

IF (DEFINED REDIS)
INCLUDE_DIRECTORIES(${REDIS_INCLUDES_DIR})
ENDIF (DEFINED REDIS)

# Set path to C-source for specific Apache version
IF (DEFINED APACHE_1_3)
  # Directive to link with liblve
  LINK_LIBRARIES(lve)

  SET(mod_hostinglimits_SRCS
	src/apache1.3/mod_hostinglimits.c
  )
ELSE (DEFINED APACHE_1_3)
  SET(mod_hostinglimits_SRCS
	src/apache2.x/mod_hostinglimits.c
)
ENDIF (DEFINED APACHE_1_3)

# Set C-source compilation flags and properties (for Linux)
SET_SOURCE_FILES_PROPERTIES(${mod_hostinglimits_SRCS} PROPERTIES COMPILE_FLAGS "-DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE")

# This code eliminates error message of cmake...
if(COMMAND cmake_policy)
     cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

# Set target module properties
ADD_LIBRARY(mod_hostinglimits MODULE ${mod_hostinglimits_SRCS})
SET_TARGET_PROPERTIES(mod_hostinglimits PROPERTIES PREFIX "" SUFFIX ".so"
                         OUTPUT_NAME "mod_hostinglimits" LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")

# --- Apache 1.3 ---------------------------------------------------------------
IF (DEFINED APACHE_1_3)

  TARGET_LINK_LIBRARIES(mod_hostinglimits)
  ADD_DEFINITIONS(-DEAPI)
  ADD_DEFINITIONS(-DAPACHE1_3)

ELSE (DEFINED APACHE_1_3)
# --- Apache 2.0 or 2.2 --------------------------------------------------------
  IF (DEFINED REDIS)
   ADD_DEFINITIONS(-DREDIS)
   IF (DEFINED NOAPR)
     TARGET_LINK_LIBRARIES(mod_hostinglimits ${REDIS_LIB_DIR})
   ELSE (DEFINED NOAPR)
     TARGET_LINK_LIBRARIES(mod_hostinglimits ${APR_LIBRARY} ${REDIS_LIB_DIR})
   ENDIF (DEFINED NOAPR)
  ELSE (DEFINED REDIS)
   TARGET_LINK_LIBRARIES(mod_hostinglimits ${APR_LIBRARY})
  ENDIF (DEFINED REDIS)

  IF (NOT DEFINED REDIS_NOUSE_MUTEX)
   IF (DEFINED HTTPD_PRG)
    MESSAGE( STATUS "Apache binary ${HTTPD_PRG}" ) 
    EXECUTE_PROCESS(COMMAND ${HTTPD_PRG} -V OUTPUT_VARIABLE verss)
    string( TOLOWER "${verss}" verss_lower )
    if(verss_lower MATCHES "prefork")
     ADD_DEFINITIONS(-DREDIS_NOUSE_MUTEX)
     MESSAGE( STATUS "NO USE MUTEX, PREFORK FOUND" ) 
    else()
     ADD_DEFINITIONS(-DREDIS_USE_MUTEX)
     MESSAGE( STATUS "USE MUTEX WORKER, EVENT FOUND" ) 
    endif()
   ENDIF (DEFINED HTTPD_PRG)
  ELSE (NOT DEFINED REDIS_NOUSE_MUTEX)
   ADD_DEFINITIONS(-DREDIS_NOUSE_MUTEX)
  ENDIF (NOT DEFINED REDIS_NOUSE_MUTEX)

  IF (DEFINED APACHE_2_2)
    ADD_DEFINITIONS(-DAPACHE2_2)
  ELSE (DEFINED APACHE_2_2)
    ADD_DEFINITIONS(-DAPACHE2_0)
    ADD_DEFINITIONS(-DCPANEL)
  ENDIF (DEFINED APACHE_2_2)

ENDIF (DEFINED APACHE_1_3)
# ------------------------------------------------------------------------------

install(TARGETS mod_hostinglimits
	DESTINATION ${HTTPD_MODULES}
	COMPONENT Runtime
	)


ENDIF (DEFINED BUILD)
