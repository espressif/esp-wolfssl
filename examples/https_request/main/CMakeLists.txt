# Embed the server root certificate into the final binary
#
# (If this was a component, we would set COMPONENT_EMBED_TXTFILES here.)
idf_component_register(SRCS "https_request_example_main.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES esp-tls esp_wifi esp_netif esp_event nvs_flash protocol_examples_common
                    EMBED_TXTFILES server_root_cert.pem)