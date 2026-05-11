idf_component_register(SRCS "wolfssl_client_demo.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES esp-wolfssl esp_wifi esp_event esp_netif
                                  nvs_flash lwip protocol_examples_common
                    EMBED_TXTFILES "server_root_cert.pem")

target_compile_definitions(${COMPONENT_LIB} PRIVATE WOLFSSL_USER_SETTINGS)
# wolfSSL's settings.h emits a #warning on xtensa about non-constant-time crypto
# implementations; downgrade that to a warning so the example builds with -Werror.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-cpp)
