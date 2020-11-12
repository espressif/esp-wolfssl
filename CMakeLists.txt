set(include_dirs port wolfssl)
set(lib_path ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/lib/${IDF_TARGET})

idf_component_register(INCLUDE_DIRS "${include_dirs}"
                    REQUIRES lwip
                    REQUIRED_IDF_TARGETS esp32 esp8266)

target_compile_options(${COMPONENT_LIB} INTERFACE -Wno-cpp)
target_compile_definitions(${COMPONENT_LIB} INTERFACE WOLFSSL_USER_SETTINGS)

if(CONFIG_ESP_DEBUG_WOLFSSL)
    if(CONFIG_ESP_WOLFSSL_SMALL_CERT_VERIFY)
        # use debug library with WOLFSSL_SMALL_CERT_VERIFY enabled
        set(lib "libwolfssl_small_cert_verify.a")
    else()
        # use debug library without WOLFSSL_SMALL_CERT_VERIFY enabled
        set(lib "libwolfssl_debug.a")
    endif()
else()
    if(CONFIG_ESP_WOLFSSL_SMALL_CERT_VERIFY)
        # use library with WOLFSSL_SMALL_CERT_VERIFY enabled (without debug)
        set(lib "libwolfssl_small_cert_verify.a")
    else()
        # use library without WOLFSSL_SMALL_CERT_VERIFY enabled (without debug)
        # This Library is USED BY DEFAULT (no wolfssl options enabled)
        set(lib "libwolfssl.a")
    endif()
endif()
# Establish dependancy of prebuilt wolfssl binaries on freertos
add_prebuilt_library(prebuilt ${lib_path}/${lib} PRIV_REQUIRES freertos)
target_link_libraries(${COMPONENT_LIB} INTERFACE prebuilt)
