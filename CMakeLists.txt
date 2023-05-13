CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(quicly)

INCLUDE(CMakePushCheckState)
INCLUDE(CheckCSourceCompiles)
INCLUDE(deps/picotls/cmake/boringssl-adjust.cmake)
INCLUDE(deps/picotls/cmake/dtrace-utils.cmake)

FIND_PACKAGE(OpenSSL REQUIRED)
cmake_path(GET OPENSSL_INCLUDE_DIR PARENT_PATH OPENSSL_BASE_DIR)
MESSAGE("Base: ${OPENSSL_BASE_DIR} ${OPENSSL_INCLUDE_DIR}")

OPTION(WITH_EXAMPLE "whether or not to build the example binary" ON)

BORINGSSL_ADJUST()
IF (OPENSSL_FOUND AND (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    MESSAGE(FATAL "OpenSSL 1.0.2 or above is missing")
ENDIF ()

CMAKE_PUSH_CHECK_STATE()
SET(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -mavx2 -maes -mpclmul -mvaes -mvpclmulqdq")
CHECK_C_SOURCE_COMPILES("int main(void) {}" CC_HAS_AESNI256)
CMAKE_POP_CHECK_STATE()
IF (CC_HAS_AESNI256)
    SET(WITH_FUSION_DEFAULT "ON")
ELSE ()
    SET(WITH_FUSION_DEFAULT "OFF")
ENDIF ()
OPTION(WITH_FUSION "whether or not to use the Fusion AES-GCM engine in the cli binary" ${WITH_FUSION_DEFAULT})

# CMake defaults to a Debug build, whereas quicly defaults to an optimized (Release) build
IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
ENDIF(NOT CMAKE_BUILD_TYPE)

SET( QUICLY_INCLUDES
    ${OPENSSL_INCLUDE_DIR}
    deps/klib
    deps/picotls/include
    deps/picotest
    include
    ${CMAKE_CURRENT_BINARY_DIR})

SET(PICOTLS_OPENSSL_FILES
    deps/picotls/lib/hpke.c
    deps/picotls/lib/openssl.c
    deps/picotls/lib/pembase64.c
    deps/picotls/lib/picotls.c)

SET(QUICLY_LIBRARY_FILES
    lib/frame.c
    lib/cc-reno.c
    lib/cc-cubic.c
    lib/cc-pico.c
    lib/defaults.c
    lib/local_cid.c
    lib/loss.c
    lib/quicly.c
    lib/ranges.c
    lib/rate.c
    lib/recvstate.c
    lib/remote_cid.c
    lib/retire_cid.c
    lib/sendstate.c
    lib/sentmap.c
    lib/streambuf.c
    ${PICOTLS_OPENSSL_FILES}
    )

IF(WIN32)
    SET(CMAKE_C_FLAGS "-D_WINDOWS=1 ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
ENDIF ()
#SET(CMAKE_C_FLAGS_DEBUG "-O0")
#SET(CMAKE_C_FLAGS_RELEASE "-O2")

#ADD_LIBRARY(picotls ${PICOTLS_OPENSSL_FILES} ${PICOTLS_WIN32COMPAT_FILES})
#TARGET_LINK_LIBRARIES(picotls LINK_PUBLIC m mswsock ws2_32)
#TARGET_INCLUDE_DIRECTORIES(picotls PUBLIC ${QUICLY_INCLUDES})
#
#set_target_properties(picotls PROPERTIES PUBLIC_HEADER "deps/picotls/include/picotls.h")

ADD_LIBRARY(quicly ${QUICLY_LIBRARY_FILES})
TARGET_LINK_LIBRARIES(quicly LINK_PUBLIC m mswsock ws2_32)
TARGET_INCLUDE_DIRECTORIES(quicly PUBLIC ${QUICLY_INCLUDES})
IF(WIN32)
    TARGET_INCLUDE_DIRECTORIES(quicly PUBLIC ${PICOTLS_WIN32COMPAT_INCLUDE_PATH} )
ENDIF ()

set_target_properties(quicly PROPERTIES PUBLIC_HEADER "include/quicly.h;deps/picotls/include/picotls.h")

INSTALL( TARGETS quicly
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include )

INSTALL( DIRECTORY include DESTINATION ${CMAKE_INSTALL_PREFIX}/ )

#INSTALL( TARGETS picotls
#        LIBRARY DESTINATION lib
#        PUBLIC_HEADER DESTINATION include )
#
#INSTALL( DIRECTORY deps/picotls/include DESTINATION ${CMAKE_INSTALL_PREFIX}/ )

# ------------ #

if( WITH_EXAMPLE )
    ADD_EXECUTABLE(examples-echo examples/echo.c)
    MESSAGE("Libs: ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS}")
    TARGET_LINK_LIBRARIES(examples-echo LINK_PUBLIC quicly mswsock ws2_32 ${OPENSSL_CRYPTO_LIBRARIES} ${CMAKE_DL_LIBS})
    IF(WIN32)
        TARGET_INCLUDE_DIRECTORIES(examples-echo PUBLIC include/ )
    ENDIF ()

    INSTALL( TARGETS examples-echo )
ENDIF ()
