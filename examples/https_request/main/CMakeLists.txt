# Embed the server root certificate into the final binary
idf_component_register(SRCS "https_request_example_main.c" "time_sync.c"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES esp-tls esp_wifi esp_timer nvs_flash
                                  esp-wolfssl protocol_examples_common
                    EMBED_TXTFILES server_root_cert.pem local_server_cert.pem)
