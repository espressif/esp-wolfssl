set(COMPONENT_SRCDIRS "wolfssl/src/"
                      "wolfssl/wolfcrypt/src"
                      "wolfssl/wolfcrypt/src/port/Espressif/"
                      "wolfssl/wolfcrypt/src/port/atmel/"
                      )

set(COMPONENT_REQUIRES lwip)

set(COMPONENT_ADD_INCLUDEDIRS
    "port"
    "wolfssl"
    )

set(COMPONENT_SRCEXCLUDE_1
    "wolfssl/wolfcrypt/src/aes_asm.S"
    "wolfssl/wolfcrypt/src/evp.c"
    "wolfssl/wolfcrypt/src/misc.c"
    "wolfssl/src/bio.c"
    "wolfssl/wolfcrypt/src/sp_x86_64_asm.S"
    "wolfssl/wolfcrypt/src/sha512_asm.S"
    "wolfssl/wolfcrypt/src/sha256_asm.S"
    "wolfssl/wolfcrypt/src/chacha_asm.S"
    "wolfssl/wolfcrypt/src/aes_gcm_asm.S"
    "wolfssl/wolfcrypt/src/poly1305_asm.S"
    "wolfssl/wolfcrypt/src/fe_x25519_asm.S"
    )

idf_component_register(SRC_DIRS "${COMPONENT_SRCDIRS}"
                        INCLUDE_DIRS "${COMPONENT_ADD_INCLUDEDIRS}"
                        REQUIRES "${COMPONENT_REQUIRES}"
                        EXCLUDE_SRCS "${COMPONENT_SRCEXCLUDE_1}"
                        )
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-cpp -Wno-maybe-uninitialized)
set_source_files_properties(wolfssl/src/ssl.c PROPERTIES COMPILE_FLAGS -Wno-format-truncation)
target_compile_definitions(${COMPONENT_LIB} PUBLIC WOLFSSL_USER_SETTINGS)
