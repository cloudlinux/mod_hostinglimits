# This script searches for installed Apache sources and determines paths to includes and libraries.
# Script is used in building RPM for standard Apache and for HSphere. Not for use with Cpanel!
# Returns next variables for each version of Apache:
# for Apache 2.2: APACHE2_2_FOUND    APACHE2_2_HTTPD_INCLUDE_DIR    APACHE2_2_APR_INCLUDE_DIR    APACHE2_2_APRUTIL_INCLUDE_DIR    APACHE2_2_APR_LIBRARY    APACHE2_2_HTTPD_MODULES
# for Apache 2.0: APACHE2_0_FOUND    APACHE2_0_HTTPD_INCLUDE_DIR    APACHE2_0_APR_INCLUDE_DIR    APACHE2_0_APRUTIL_INCLUDE_DIR    APACHE2_0_APR_LIBRARY    APACHE2_0_HTTPD_MODULES
# for Apache 1.3: APACHE1_3_FOUND    HTTPD_INCLUDE_DIR              HTTPD_MODULES



# --- Apache 2.2 ---------------------------------------------------------------------------------------------------------------------------
SET(APR_NAME apr-1)
SET(APRUTIL_NAME aprutil-1)

FIND_PATH (APACHE2_2_INCLUDES_DIR 
   NAMES
      apr.h
      apu.h
      httpd.h
   PATHS 
      /usr/local/include/httpd
      /usr/include/httpd
      /usr/local/include/apr-1
      /usr/local/include/apr-1.0
      /usr/include/apr-1
      /usr/include/apr-1.0
)

FIND_PATH (APACHE2_2_LIBRARIES_DIR 
   NAMES 
      ${APR_NAME}
      ${APRUTIL_NAME}
   PATHS 
      /usr/local/lib
      /usr/lib
)

# APR first.
FIND_PATH (APACHE2_2_APR_INCLUDE_DIR 
   NAMES 
      apr.h
   PATHS 
      ${APACHE2_2_INCLUDES_DIR}
      /usr/local/include/apr-1
      /usr/local/include/apr-1.0
      /usr/include/apr-1
      /usr/include/apr-1.0
)

FIND_LIBRARY (APACHE2_2_APR_LIBRARY 
   NAMES 
      ${APR_NAME}
   PATHS 
      ${APACHE2_2_LIBRARIES_DIR}
      /usr/local/lib
      /usr/lib
      /etc/httpd/lib/
)



# Next,  APRUTIL.
FIND_PATH (APACHE2_2_APRUTIL_INCLUDE_DIR 
   NAMES 
      apu.h
   PATHS
      ${APACHE2_2_INCLUDES_DIR}
      /usr/local/include/apr-1
      /usr/local/include/apr-1.0
      /usr/include/apr-1
      /usr/include/apr-1.0
)

FIND_LIBRARY (APACHE2_2_APRUTIL_LIBRARY 
   NAMES 
      ${APRUTIL_NAME}
   PATHS 
      ${APACHE2_2_LIBRARIES_DIR}
      /usr/local/lib
      /usr/lib 
)



# Next,  HTTPD.
FIND_PATH (APACHE2_2_HTTPD_INCLUDE_DIR 
   NAMES 
      httpd.h
   PATHS
      ${APACHE2_2_INCLUDES_DIR}
      /usr/local/include/httpd
      /usr/include/httpd
      /usr/include/apache
)

# Next, bin directory
FIND_PATH (APACHE2_2_HTTPD_BIN
   NAMES
      apachectl
   PATHS
      /usr/local/httpd/bin
      /etc/httpd/bin
)

# Next, module directory
FIND_PATH (APACHE2_2_HTTPD_MODULES                                                                                                                                    
NAMES                                                                                                                                                    
    mod_alias.so
PATHS                        
    /usr/local/httpd/modules                                                                                                                              
    /etc/httpd/modules                                                                                                                                    
)

# *** This code is for status messages output only ***************************************
IF (APACHE2_2_APR_INCLUDE_DIR AND APACHE2_2_APR_LIBRARY)
   SET (APACHE2_2_APR_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Portable Runtime: ${APACHE2_2_APR_INCLUDE_DIR}, ${APACHE2_2_APR_LIBRARY}")
ELSE (APACHE2_2_APR_INCLUDE_DIR AND APACHE2_2_APR_LIBRARY)
   SET (APACHE2_2_APR_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache Portable Runtime")
ENDIF (APACHE2_2_APR_INCLUDE_DIR AND APACHE2_2_APR_LIBRARY)

IF (APACHE2_2_APRUTIL_INCLUDE_DIR AND APACHE2_2_APRUTIL_LIBRARY)
   SET(APACHE2_2_APRUTIL_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Portable Runtime Utils: ${APACHE2_2_APRUTIL_INCLUDE_DIR}, ${APACHE2_2_APRUTIL_LIBRARY}")
ELSE (APACHE2_2_APRUTIL_INCLUDE_DIR AND APACHE2_2_APRUTIL_LIBRARY)
   SET(APACHE2_2_APRUTIL_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache Portable Runtime Utils")
ENDIF (APACHE2_2_APRUTIL_INCLUDE_DIR AND APACHE2_2_APRUTIL_LIBRARY)

IF (APACHE2_2_HTTPD_BIN AND APACHE2_2_HTTPD_MODULES)
   SET(APACHE2_2_HTTPD_BIN_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Bin Directory: ${APACHE2_2_HTTPD_BIN}, ${APACHE2_2_HTTPD_MODULES}")
ELSE (APACHE2_2_HTTPD_BIN AND APACHE2_2_HTTPD_MODULES)
   SET(APACHE2_2_HTTPD_BIN_FOUND FALSE)
   MESSAGE (STATUS "Not Found Apache Bin Directory: ${APACHE2_2_HTTPD_BIN}, ${APACHE2_2_HTTPD_MODULES}")
ENDIF(APACHE2_2_HTTPD_BIN AND APACHE2_2_HTTPD_MODULES)
# ****************************************************************************************

# Check if all needed directories are found
IF (APACHE2_2_HTTPD_INCLUDE_DIR AND APACHE2_2_APR_INCLUDE_DIR AND APACHE2_2_APRUTIL_INCLUDE_DIR AND APACHE2_2_APR_LIBRARY)
  SET (APACHE2_2_FOUND TRUE)
  MESSAGE (STATUS "Found Apache2.2: ${APACHE2_2_HTTPD_INCLUDE_DIR}")

ELSE (APACHE2_2_HTTPD_INCLUDE_DIR AND APACHE2_2_APR_INCLUDE_DIR AND APACHE2_2_APRUTIL_INCLUDE_DIR AND APACHE2_2_APR_LIBRARY)
  SET (APACHE2_2_FOUND FALSE)
  MESSAGE (STATUS "Can't find Apache2.2: ${APACHE2_2_HTTPD_INCLUDE_DIR}")

ENDIF (APACHE2_2_HTTPD_INCLUDE_DIR AND APACHE2_2_APR_INCLUDE_DIR AND APACHE2_2_APRUTIL_INCLUDE_DIR AND APACHE2_2_APR_LIBRARY)




# --- Apache 2.2 HSPHERE ---------------------------------------------------------------------------------------------------------------------------

FIND_PATH (APACHE2_0_INCLUDES_DIR 
   NAMES
      apr.h
      apu.h
      httpd.h
   PATHS 
      /hsphere/shared/apache2/include
)

FIND_PATH (APACHE2_0_LIBRARIES_DIR 
   NAMES 
      ${APR_NAME}
      ${APRUTIL_NAME}
   PATHS 
      /hsphere/shared/apache2/lib
)

# APR first.
FIND_PATH (APACHE2_0_APR_INCLUDE_DIR 
   NAMES 
      apr.h
   PATHS 
      /hsphere/shared/apache2/include
)

FIND_LIBRARY (APACHE2_0_APR_LIBRARY 
   NAMES 
      ${APR_NAME}
   PATHS 
      ${APACHE2_0_LIBRARIES_DIR}
      /hsphere/shared/apache2/lib
)



# Next,  APRUTIL.
FIND_PATH (APACHE2_0_APRUTIL_INCLUDE_DIR 
   NAMES 
      apu.h
   PATHS
      ${APACHE2_0_INCLUDES_DIR}
      /hsphere/shared/apache2/include
)

FIND_LIBRARY (APACHE2_0_APRUTIL_LIBRARY 
   NAMES 
      ${APRUTIL_NAME}
   PATHS 
      ${APACHE2_0_LIBRARIES_DIR}
      /hsphere/shared/apache2/lib 
)



# Next,  HTTPD.
FIND_PATH (APACHE2_0_HTTPD_INCLUDE_DIR 
   NAMES 
      httpd.h
   PATHS
      ${APACHE2_0_INCLUDES_DIR}
      /hsphere/shared/apache2/include
)

# Next, bin directory
SET(APACHE2_0_HTTPD_BIN /hsphere/shared/apache2/bin)

# Next, module directory
SET(APACHE2_0_HTTPD_MODULES /hsphere/shared/apache2/modules)

# *** This code is for status messages output only ***************************************
IF (APACHE2_0_APR_INCLUDE_DIR AND APACHE2_0_APR_LIBRARY)
   SET (APACHE2_0_APR_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Portable Runtime: ${APACHE2_0_APR_INCLUDE_DIR}, ${APACHE2_0_APR_LIBRARY}")
ELSE (APACHE2_0_APR_INCLUDE_DIR AND APACHE2_0_APR_LIBRARY)
   SET (APACHE2_0_APR_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache Portable Runtime")
ENDIF (APACHE2_0_APR_INCLUDE_DIR AND APACHE2_0_APR_LIBRARY)

IF (APACHE2_0_APRUTIL_INCLUDE_DIR AND APACHE2_0_APRUTIL_LIBRARY)
   SET(APACHE2_0_APRUTIL_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Portable Runtime Utils: ${APACHE2_0_APRUTIL_INCLUDE_DIR}, ${APACHE2_0_APRUTIL_LIBRARY}")
ELSE (APACHE2_0_APRUTIL_INCLUDE_DIR AND APACHE2_0_APRUTIL_LIBRARY)
   SET(APACHE2_0_APRUTIL_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache Portable Runtime Utils")
ENDIF (APACHE2_0_APRUTIL_INCLUDE_DIR AND APACHE2_0_APRUTIL_LIBRARY)

IF (APACHE2_0_HTTPD_BIN AND APACHE2_0_HTTPD_MODULES)
   SET(APACHE2_0_HTTPD_BIN_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Bin Directory: ${APACHE2_0_HTTPD_BIN}, ${APACHE2_0_HTTPD_MODULES}")
ELSE (APACHE2_0_HTTPD_BIN AND APACHE2_0_HTTPD_MODULES)
   SET(APACHE2_0_HTTPD_BIN_FOUND FALSE)
   MESSAGE (STATUS "Not Found Apache Bin Directory: ${APACHE2_0_HTTPD_BIN}, ${APACHE2_0_HTTPD_MODULES}")
ENDIF(APACHE2_0_HTTPD_BIN AND APACHE2_0_HTTPD_MODULES)
# ****************************************************************************************

# Check if all needed directories are found
IF (APACHE2_0_HTTPD_INCLUDE_DIR AND APACHE2_0_APR_INCLUDE_DIR AND APACHE2_0_APRUTIL_INCLUDE_DIR AND APACHE2_0_APR_LIBRARY)
  SET (APACHE2_0_FOUND TRUE)
  MESSAGE (STATUS "Found Apache2.0: ${APACHE2_0_HTTPD_INCLUDE_DIR}")

ELSE (APACHE2_0_HTTPD_INCLUDE_DIR AND APACHE2_0_APR_INCLUDE_DIR AND APACHE2_0_APRUTIL_INCLUDE_DIR AND APACHE2_0_APR_LIBRARY)
  SET (APACHE2_0_FOUND FALSE)
  MESSAGE (STATUS "Can't find Apache2.0: ${APACHE2_0_HTTPD_INCLUDE_DIR}")

ENDIF (APACHE2_0_HTTPD_INCLUDE_DIR AND APACHE2_0_APR_INCLUDE_DIR AND APACHE2_0_APRUTIL_INCLUDE_DIR AND APACHE2_0_APR_LIBRARY)




# --- Apache 1.3 ---------------------------------------------------------------------------------------------------------------------------
FIND_PATH (APACHE_INCLUDES_DIR 
   NAMES
      httpd.h
   PATHS 
      /hsphere/shared/apache/include
)

# Next,  HTTPD.
FIND_PATH (HTTPD_INCLUDE_DIR 
   NAMES 
      httpd.h
   PATHS
      ${APACHE_INCLUDES_DIR}
      /hsphere/shared/apache/include
)

# Next, bin directory
SET(HTTPD_BIN /hsphere/shared/apache/bin)

#Next, module directory
SET(HTTPD_MODULES /hsphere/shared/apache/libexec)

# Print diagnostic messages
IF (HTTPD_BIN AND HTTPD_MODULES)
   SET(HTTPD_BIN_FOUND TRUE)
   MESSAGE (STATUS "Found Apache Bin Directory: ${HTTPD_BIN}, ${HTTPD_MODULES}")
ELSE (HTTPD_BIN AND HTTPD_MODULES)
   SET(HTTPD_BIN_FOUND FALSE)
   MESSAGE (STATUS "Not Found Apache Bin Directory: ${HTTPD_BIN}, ${HTTPD_MODULES}")
ENDIF(HTTPD_BIN AND HTTPD_MODULES)

# Return result
IF (HTTPD_INCLUDE_DIR)
   SET (APACHE1_3_FOUND TRUE)
   MESSAGE (STATUS "Found Apache1.3: ${HTTPD_INCLUDE_DIR}")
ELSE (HTTPD_INCLUDE_DIR)
   SET (APACHE1_3_FOUND FALSE)
   MESSAGE (STATUS "Can't find Apache1.3: ${HTTPD_INCLUDE_DIR}")
ENDIF (HTTPD_INCLUDE_DIR)

