set(COMPONENT_SRCDIRS "wolfssl/src/"
                      "wolfssl/wolfcrypt/src"
                      "port"
                      )

# Certificate-bundle support (wolfSSL equivalent of MBEDTLS_CERTIFICATE_BUNDLE).
# The implementation ships in the wolfSSL submodule's Espressif port; compile it
# only when the feature is enabled.
set(WOLFSSL_CRT_BUNDLE_DIR "wolfssl/wolfcrypt/src/port/Espressif/esp_crt_bundle")
if(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE)
    list(APPEND COMPONENT_SRCDIRS "${WOLFSSL_CRT_BUNDLE_DIR}")
endif()

set(COMPONENT_REQUIRES lwip)
# esp_system: ESP_SYSTEM_INIT_FN auto-registration; esp_hw_support: esp_fill_random()
# used by esp_wolfssl_seed.c (wc_GenerateSeed).
set(COMPONENT_PRIV_REQUIRES esp_system esp_hw_support)

list(APPEND COMPONENT_REQUIRES esp-tls)

set(COMPONENT_ADD_INCLUDEDIRS
    "port"
    "wolfssl"
    )

list(APPEND COMPONENT_ADD_INCLUDEDIRS "include")

set(COMPONENT_SRCEXCLUDE_1
    # x86/x64 assembly files (not compatible with RISC-V/Xtensa)
    "wolfssl/wolfcrypt/src/aes_asm.S"
    "wolfssl/wolfcrypt/src/evp.c"
    "wolfssl/src/bio.c"
    "wolfssl/wolfcrypt/src/sp_x86_64_asm.S"
    "wolfssl/wolfcrypt/src/sp_sm2_x86_64_asm.S"
    "wolfssl/wolfcrypt/src/sha512_asm.S"
    "wolfssl/wolfcrypt/src/sha256_asm.S"
    "wolfssl/wolfcrypt/src/sha3_asm.S"
    "wolfssl/wolfcrypt/src/sm3_asm.S"
    "wolfssl/wolfcrypt/src/chacha_asm.S"
    "wolfssl/wolfcrypt/src/aes_gcm_asm.S"
    "wolfssl/wolfcrypt/src/aes_gcm_x86_asm.S"
    "wolfssl/wolfcrypt/src/aes_xts_asm.S"
    "wolfssl/wolfcrypt/src/poly1305_asm.S"
    "wolfssl/wolfcrypt/src/fe_x25519_asm.S"
    "wolfssl/wolfcrypt/src/wc_mlkem_asm.S"
    "wolfssl/wolfcrypt/src/wc_mldsa_asm.S"
    # External library wrappers (require liboqs, etc. - we use native implementations)
    "wolfssl/wolfcrypt/src/ext_mlkem.c"
    "wolfssl/wolfcrypt/src/ext_lms.c"
    "wolfssl/wolfcrypt/src/ext_xmss.c"
    )

idf_component_register(SRC_DIRS "${COMPONENT_SRCDIRS}"
                        INCLUDE_DIRS "${COMPONENT_ADD_INCLUDEDIRS}"
                        REQUIRES "${COMPONENT_REQUIRES}"
                        PRIV_REQUIRES "${COMPONENT_PRIV_REQUIRES}"
                        EXCLUDE_SRCS "${COMPONENT_SRCEXCLUDE_1}"
                        )

if(CONFIG_ESP_TLS_CUSTOM_STACK)
    # Nothing references esp_tls_wolfssl.c directly, so the linker would drop it
    # (and the ESP_SYSTEM_INIT_FN auto-registration entry with it). Force just
    # that object into the link instead of WHOLE_ARCHIVE-ing the entire
    # component, which would pull every wolfSSL object (incl. unused PQC code)
    # into the binary.
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u esp_wolfssl_register_stack")
endif()

# esp_tls_private.h defines struct esp_tls; the custom-stack interface
# (esp_tls_custom_stack.h) requires backends to populate tls->priv_ctx /
# tls->priv_ssl, so this private header is needed by design.
# Validated against ESP-IDF master (v6.2-dev).
idf_component_get_property(esp_tls_dir esp-tls COMPONENT_DIR)
target_include_directories(${COMPONENT_LIB} PRIVATE "${esp_tls_dir}/private_include")

# Generate and embed the trusted-root certificate bundle for wolfSSL.
# gen_crt_bundle.py writes a fixed file 'x509_crt_bundle_wolfssl' into its
# working directory; target_add_binary_data() then embeds it, producing the
# _binary_x509_crt_bundle_wolfssl_start/end symbols that esp_crt_bundle.c uses.
if(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE)
    idf_build_get_property(python PYTHON)
    set(crt_bundle_gen_dir "${COMPONENT_DIR}/${WOLFSSL_CRT_BUNDLE_DIR}")
    set(crt_bundle_out "${CMAKE_CURRENT_BINARY_DIR}/x509_crt_bundle_wolfssl")
    set(crt_inputs "${crt_bundle_gen_dir}/cacrt_all.pem" "${crt_bundle_gen_dir}/cacrt_local.pem")
    add_custom_command(OUTPUT "${crt_bundle_out}"
        COMMAND ${python} "${crt_bundle_gen_dir}/gen_crt_bundle.py" -q --input ${crt_inputs}
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        DEPENDS ${crt_inputs} "${crt_bundle_gen_dir}/gen_crt_bundle.py"
        VERBATIM)
    add_custom_target(wolfssl_crt_bundle DEPENDS "${crt_bundle_out}")
    add_dependencies(${COMPONENT_LIB} wolfssl_crt_bundle)
    target_add_binary_data(${COMPONENT_LIB} "${crt_bundle_out}" BINARY)
    # esp_crt_bundle.c gates its whole implementation behind the legacy
    # built-in-backend macro CONFIG_ESP_TLS_USING_WOLFSSL. In the custom-stack
    # model that macro is never set, so define it just for this file to enable
    # the bundle code (it is the wolfSSL backend here regardless).
    # esp_crt_bundle.c does not include settings.h first, so WOLFSSL_ESPIDF
    # (defined via user_settings.h) is not set when its top-level guard is
    # evaluated and the whole file compiles to nothing. Force settings.h first,
    # matching every other wolfSSL source.
    set_source_files_properties("${WOLFSSL_CRT_BUNDLE_DIR}/esp_crt_bundle.c"
        PROPERTIES
        COMPILE_DEFINITIONS "CONFIG_ESP_TLS_USING_WOLFSSL=1"
        COMPILE_FLAGS "-include wolfssl/wolfcrypt/settings.h")
endif()

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-cpp -Wno-maybe-uninitialized)
set_source_files_properties(wolfssl/src/ssl.c PROPERTIES COMPILE_FLAGS "-Wno-format-truncation -Wno-char-subscripts")
set_source_files_properties(wolfssl/wolfcrypt/src/random.c PROPERTIES COMPILE_FLAGS "-Wno-implicit-function-declaration")
# NO_ESP32_CRYPT must be defined BEFORE WOLFSSL_USER_SETTINGS to disable hardware crypto
# The order matters: settings.h checks these macros before including user_settings.h
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    NO_ESP32_CRYPT
    NO_WOLFSSL_ESP32_CRYPT_HASH
    NO_WOLFSSL_ESP32_CRYPT_AES
    NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
    NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
    NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
    NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
    WOLFSSL_USER_SETTINGS
)
