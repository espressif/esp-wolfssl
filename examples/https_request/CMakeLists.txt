# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# (Not part of the boilerplate)
# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common "../../")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Trim the build to only the components that main (and its dependency chain)
# actually needs. esp-wolfssl is added explicitly because the example does not
# reference any of its symbols directly -- it auto-registers as the custom
# esp-tls stack via ESP_SYSTEM_INIT_FN.
idf_build_set_property(MINIMAL_BUILD ON)
set(COMPONENTS main esp-wolfssl)

project(https_request)
