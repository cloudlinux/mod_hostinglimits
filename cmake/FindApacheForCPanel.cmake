# This script searches for installed Apache sources and determines paths to includes and libraries.
# Script is used with Cpanel only.
# Returns next variables for each version of Apache:
# for Apache 2.2: APACHE2_2    HTTPD_INCLUDE_DIR    HTTPD_MODULES    APR_INCLUDE_DIR    APRUTIL_INCLUDE_DIR    APR_LIBRARY
# for Apache 2.0: APACHE2_0    HTTPD_INCLUDE_DIR    HTTPD_MODULES    APR_INCLUDE_DIR    APRUTIL_INCLUDE_DIR    APR_LIBRARY
# for Apache 1.3: APACHE1_3    HTTPD_INCLUDE_DIR    HTTPD_MODULES

IF (NOT DEFINED APACHECTL)
FIND_PROGRAM(APACHECTL NAMES apachectl
PATHS
      /usr/local/apache/bin
      /usr/local/apache2/bin
      /usr/local/httpd/bin
      /etc/httpd/bin
      /usr/sbin
)
ENDIF (NOT DEFINED APACHECTL)

IF (APACHECTL)
    EXECUTE_PROCESS(COMMAND ${APACHECTL} -v OUTPUT_VARIABLE vers)
    STRING(SUBSTRING "${vers}" 23 3 vrvar)
    MESSAGE(STATUS "Version ${vrvar}...")
    IF ("${vrvar}" STREQUAL "2.0")
	SET(APACHE_2_0 TRUE)
	MESSAGE(STATUS "apache 2.0 detected...")
    ELSE ("${vrvar}" STREQUAL "2.0")
	IF ("${vrvar}" STREQUAL "2.2")
	    SET(APACHE_2_2 TRUE)
	    MESSAGE(STATUS "apache 2.2 detected...")
	ELSE ("${vrvar}" STREQUAL "2.2")
	    IF ("${vrvar}" STREQUAL "2.4")
		SET(APACHE_2_2 TRUE)
		SET(APACHE_2_4 TRUE)
		MESSAGE(STATUS "apache 2.4 detected...")
	    ELSE ("${vrvar}" STREQUAL "2.4")
		SET(APACHE_1_3 TRUE)
		MESSAGE(STATUS "apache 1.3 detected...")
	    ENDIF ("${vrvar}" STREQUAL "2.4")
	ENDIF ("${vrvar}" STREQUAL "2.2")
    ENDIF ("${vrvar}" STREQUAL "2.0")
ELSE (APACHECTL)
    SET(APACHE_1_3 TRUE)
    MESSAGE(STATUS "Default apache 1.3 detected...")
ENDIF (APACHECTL)




# --- Apache 2.2 or Apache 2.0 -------------------------------------------------------------------------------------------------------------
IF ((DEFINED APACHE_2_2) OR (DEFINED APACHE_2_0))

IF (DEFINED APACHE_2_2)
  SET(APR_NAME apr-1)
  SET(APRUTIL_NAME aprutil-1)
ELSE (DEFINED APACHE_2_2)
  SET(APR_NAME apr-0)
  SET(APRUTIL_NAME aprutil-0)
ENDIF (DEFINED APACHE_2_2)

IF (NOT DEFINED APACHE_INCLUDES_DIR)
FIND_PATH (APACHE_INCLUDES_DIR 
   NAMES
      apr.h
      apu.h
      httpd.h
   PATHS 
      /usr/local/apache/include
      /usr/local/apache2/include
      /usr/local/include/httpd
      /usr/include/httpd
      /usr/local/include/apr-1
      /usr/local/include/apr-1.0
      /usr/include/apr-1
      /usr/include/apr-1.0
      /usr/include/apache
)
ENDIF (NOT DEFINED APACHE_INCLUDES_DIR)

IF (NOT DEFINED APACHE_LIBRARIES_DIR)
FIND_PATH (APACHE_LIBRARIES_DIR 
   NAMES 
      ${APR_NAME}
      ${APRUTIL_NAME}
   PATHS 
      /usr/local/apache/lib
      /usr/local/apache2/lib
      /usr/local/lib
      /usr/lib
)
ENDIF (NOT DEFINED APACHE_LIBRARIES_DIR)


# APR first.
IF (NOT DEFINED APR_INCLUDE_DIR)
FIND_PATH (APR_INCLUDE_DIR 
   NAMES 
      apr.h
   PATHS 
      ${APACHE_INCLUDES_DIR}
      /usr/local/apache/include
      /usr/local/apache2/include
      /usr/local/include/apr-1
      /usr/local/include/apr-1.0
      /usr/include/apr-1
      /usr/include/apr-1.0
      /opt/cpanel/ea-apr15/include/apr-1
)
ENDIF (NOT DEFINED APR_INCLUDE_DIR)

IF(NOT DEFINED APR_LIBRARY)
FIND_LIBRARY (APR_LIBRARY 
   NAMES 
      ${APR_NAME}
   PATHS 
      ${APACHE_LIBRARIES_DIR}
      /usr/local/apache/lib
      /usr/local/apache2/lib
      /usr/local/lib
      /usr/lib
      /etc/httpd/lib/
      /usr/lib/apache/
      /opt/cpanel/ea-apr15/lib64
      /opt/cpanel/ea-apr15/lib
)
ENDIF(NOT DEFINED APR_LIBRARY)

IF (APR_INCLUDE_DIR AND APR_LIBRARY)
   SET (APR_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Portable Runtime: ${APR_INCLUDE_DIR}, ${APR_LIBRARY}")
ELSE (APR_INCLUDE_DIR AND APR_LIBRARY)
   SET (APR_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache Portable Runtime")
ENDIF (APR_INCLUDE_DIR AND APR_LIBRARY)



# Next,  APRUTIL.
IF (NOT DEFINED APRUTIL_INCLUDE_DIR)
FIND_PATH (APRUTIL_INCLUDE_DIR 
   NAMES 
      apu.h
   PATHS
      ${APACHE_INCLUDES_DIR}
      /usr/local/apache/include
      /usr/local/apache2/include
      /usr/local/include/apr-1
      /usr/local/include/apr-1.0
      /usr/include/apr-1
      /usr/include/apr-1.0
      /opt/cpanel/ea-apr15/include/apr-1
)
ENDIF (NOT DEFINED APRUTIL_INCLUDE_DIR)

IF(NOT DEFINED APRUTIL_LIBRARY)
FIND_LIBRARY (APRUTIL_LIBRARY 
   NAMES 
      ${APRUTIL_NAME}
   PATHS 
      ${APACHE_LIBRARIES_DIR}
      /usr/local/apache/lib
      /usr/local/apache2/lib 
      /usr/local/lib
      /usr/lib
      /usr/lib/apache/ 
)
ENDIF(NOT DEFINED APRUTIL_LIBRARY)

IF (APRUTIL_INCLUDE_DIR AND APRUTIL_LIBRARY)
   SET(APRUTIL_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Portable Runtime Utils: ${APRUTIL_INCLUDE_DIR}, ${APRUTIL_LIBRARY}")
ELSE (APRUTIL_INCLUDE_DIR AND APRUTIL_LIBRARY)
   SET(APRUTIL_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache Portable Runtime Utils")
ENDIF (APRUTIL_INCLUDE_DIR AND APRUTIL_LIBRARY)



# Next,  HTTPD.
IF (NOT DEFINED HTTPD_INCLUDE_DIR)
FIND_PATH (HTTPD_INCLUDE_DIR 
   NAMES 
      httpd.h
   PATHS
      ${APACHE_INCLUDES_DIR}
      /usr/local/apache/include
      /usr/local/apache2/include
      /usr/local/include/httpd
      /usr/include/httpd
      /usr/include/apache
      /usr/include/apache2
)
ENDIF (NOT DEFINED HTTPD_INCLUDE_DIR)

# Next, bin directory
IF (NOT DEFINED HTTPD_BIN)
FIND_PATH (HTTPD_BIN
   NAMES
      apachectl
   PATHS
      /usr/local/apache/bin
      /usr/local/apache2/bin
      /usr/local/httpd/bin
      /etc/httpd/bin
)
ENDIF (NOT DEFINED HTTPD_BIN)
#Next, module directory

IF (NOT DEFINED HTTPD_PRG)
FIND_PROGRAM(HTTPD_PRG NAMES 
    httpd
    apache
    httpd2
    apache2
PATHS
      /usr/local/apache/bin
      /usr/local/apache2/bin
      /usr/local/httpd/bin
      /etc/httpd/bin
      /usr/sbin
)
ENDIF (NOT DEFINED HTTPD_PRG)


IF (NOT DEFINED HTTPD_MODULES)
SET(PERHAPS_HTTPD_MODULES_PATHES /usr/local/apache/libexec /usr/local/apache/modules /usr/local/apache2/modules /usr/local/httpd/modules /etc/httpd/modules /usr/lib/apache /etc/apache2/modules)
FOREACH(checkDir ${PERHAPS_HTTPD_MODULES_PATHES})
    IF(EXISTS "${checkDir}" AND IS_DIRECTORY "${checkDir}")
      SET(HTTPD_MODULES "${checkDir}")
      BREAK()
    ENDIF(EXISTS "${checkDir}" AND IS_DIRECTORY "${checkDir}")
ENDFOREACH(checkDir ${PERHAPS_HTTPD_MODULES_PATHES})
ENDIF (NOT DEFINED HTTPD_MODULES)

IF(NOT DEFINED HTTPD_MODULES)
 FIND_PATH (HTTPD_MODULES                                                                                                                                    
 NAMES                                                                                                                                                    
      libphp5.so                                                                                                                                            
      mod_suphp.so                                                                                                                                           
      mod_disable_suexec.so                                                                                                                                  
 PATHS                        
     /usr/local/apache/libexec                                                                                                                            
     /usr/local/apache/modules                                                                                                                             
     /usr/local/apache2/modules                                                                                                                           
     /usr/local/httpd/modules                                                                                                                              
     /etc/httpd/modules                                                                                                                                    
     /usr/lib/apache
     /etc/apache2/modules
 )
ENDIF(NOT DEFINED HTTPD_MODULES) 

IF (HTTPD_BIN AND HTTPD_MODULES)
   SET(HTTPD_BIN_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Bin Directory: ${HTTPD_BIN}, ${HTTPD_MODULES}")
ELSE (HTTPD_BIN AND HTTPD_MODULES)
   SET(HTTPD_BIN_FOUND FALSE)
   MESSAGE (STATUS "Not Found Apache Bin Directory: ${HTTPD_BIN}, ${HTTPD_MODULES}")
ENDIF(HTTPD_BIN AND HTTPD_MODULES)

IF (HTTPD_INCLUDE_DIR)
  SET (APACHE2_FOUND TRUE)
  MESSAGE (STATUS "Found Apache2: ${HTTPD_INCLUDE_DIR}")
ELSE (HTTPD_INCLUDE_DIR)
  SET (APACHE2_FOUND FALSE)
  MESSAGE (STATUS "Can't find Apache2: ${HTTPD_INCLUDE_DIR}")
ENDIF (HTTPD_INCLUDE_DIR)





# --- Apache 1.3 ---------------------------------------------------------------------------------------------------------------------------
ELSE ((DEFINED APACHE_2_2) OR (DEFINED APACHE_2_0))


IF(NOT DEFINED APACHE_INCLUDES_DIR)
FIND_PATH (APACHE_INCLUDES_DIR 
   NAMES
      httpd.h
   PATHS 
      /usr/local/apache/include
      /usr/include/apache
)
ENDIF(NOT DEFINED APACHE_INCLUDES_DIR)

# Next,  HTTPD.
IF(NOT DEFINED HTTPD_INCLUDE_DIR)
FIND_PATH (HTTPD_INCLUDE_DIR 
   NAMES 
      httpd.h
   PATHS
      ${APACHE_INCLUDES_DIR}
      /usr/local/apache/include
      /usr/include/apache
)
ENDIF(NOT DEFINED HTTPD_INCLUDE_DIR)

# Next, bin directory
IF(NOT DEFINED HTTPD_BIN)
FIND_PATH (HTTPD_BIN
   NAMES
      apachectl
   PATHS
      /usr/local/apache/bin
      /usr/sbin
)
ENDIF(NOT DEFINED HTTPD_BIN)

#Next, module directory
IF(NOT DEFINED HTTPD_MODULES)
FIND_PATH (HTTPD_MODULES                                                                                                                                    
NAMES                                                                                                                                                    
     libphp5.so                                                                                                                                            
     mod_suphp.so                                                                                                                                           
     mod_disable_suexec.so                                                                                                                                  
PATHS                        
    /usr/local/apache/libexec                                                                                                                            
    /usr/local/apache/modules                                                                                                                             
    /usr/local/apache2/modules                                                                                                                           
    /usr/local/httpd/modules                                                                                                                              
    /etc/httpd/modules                                                                                                                                    
) 
ENDIF(NOT DEFINED HTTPD_MODULES)

IF (HTTPD_BIN AND HTTPD_MODULES)
   SET(HTTPD_BIN_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Bin Directory: ${HTTPD_BIN}, ${HTTPD_MODULES}")
ELSE (HTTPD_BIN AND HTTPD_MODULES)
   SET(HTTPD_BIN_FOUND FALSE)
   MESSAGE (STATUS "Not Found Apache Bin Directory: ${HTTPD_BIN}, ${HTTPD_MODULES}")
ENDIF(HTTPD_BIN AND HTTPD_MODULES)

IF (HTTPD_INCLUDE_DIR)
   SET (APACHE13_FOUND TRUE)
   MESSAGE (STATUS "Found Apache1.3: ${HTTPD_INCLUDE_DIR}")
ELSE (HTTPD_INCLUDE_DIR)
   SET (APACHE13_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache1.3: ${HTTPD_INCLUDE_DIR}")
ENDIF (HTTPD_INCLUDE_DIR)



ENDIF ((DEFINED APACHE_2_2) OR (DEFINED APACHE_2_0))

IF (DEFINED REDIS)

IF (NOT DEFINED REDIS_INCLUDES_DIR)
FIND_PATH (REDIS_INCLUDES_DIR 
   NAMES
      hiredis.h
   PATHS 
      /usr/local/include/hiredis
     /usr/include/hiredis
)
ENDIF (NOT DEFINED REDIS_INCLUDES_DIR)

IF (NOT DEFINED REDIS_LIB_DIR)
FIND_LIBRARY (REDIS_LIB_DIR 
   NAMES
      libhiredis.so
   PATHS 
      /usr/local/lib
      /usr/local/lib64
      /usr/lib
      /usr/lib64
      /lib
      /lib64
)

ENDIF (NOT DEFINED REDIS_LIB_DIR)

ENDIF (DEFINED REDIS)