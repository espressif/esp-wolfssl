#
# Component Makefile
#

COMPONENT_SRCDIRS := wolfssl/src wolfssl/wolfcrypt/src
COMPONENT_SRCDIRS += wolfssl/wolfcrypt/src/port/Espressif
COMPONENT_SRCDIRS += wolfssl/wolfcrypt/src/port/atmel

COMPONENT_ADD_INCLUDEDIRS := port wolfssl

CFLAGS +=-DWOLFSSL_USER_SETTINGS -Wno-cpp -Wno-maybe-uninitialized

COMPONENT_OBJEXCLUDE := wolfssl/wolfcrypt/src/aes_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/evp.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/misc.o
COMPONENT_OBJEXCLUDE += wolfssl/src/bio.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/sp_x86_64_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/sha256_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/sha512_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/chacha_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/aes_gcm_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/poly1305_asm.o
COMPONENT_OBJEXCLUDE += wolfssl/wolfcrypt/src/fe_x25519_asm.o
