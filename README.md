ESP-WOLFSSL
===========

# Licensing


---
**IMPORTANT NOTE**

Until March 2021, this repository contained binary distribution of wolfSSL libraries, which could be used royalty-free on all Espressif MCU products. This royalty-free binary distribution is not available anymore.

This repository now uses upstream wolfSSL GitHub pointer as submodule and can still be used as ESP-IDF component. Please follow licensing requirements per [wolfssl/LICENSING](https://github.com/wolfSSL/wolfssl/blob/master/LICENSING)

---

# Requirements
- ESP_IDF
 - To run the examples user must have installed ESP-IDF version v4.1 (minimum supported) from https://github.com/espressif/esp-idf.git
 - The IDF_PATH should be set as an environment variable

# Getting Started

- Please clone this repository using,
 ```
 git clone --recursive https://github.com/espressif/esp-wolfssl
 ```
- Please refer to https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html for setting ESP-IDF
 - ESP-IDF can be downloaded from https://github.com/espressif/esp-idf/
 - ESP-IDF v4.1 and above is recommended version
- Please refer to [example README](examples/README.md) for more information on setting up examples

# Using esp-wolfssl as a custom esp-tls stack (ESP-IDF 5.x / 6.x)

From ESP-IDF 5.x onwards, `esp-tls` supports pluggable TLS backends via
`CONFIG_ESP_TLS_CUSTOM_STACK`. `esp-wolfssl` registers itself automatically
with `esp-tls` during system init (via `ESP_SYSTEM_INIT_FN`), so applications
that already use the `esp_tls_*` APIs (or any higher-level component built on
top — `esp_http_client`, `esp_https_ota`, `esp_https_server`, `esp-mqtt`, etc.)
work unchanged. **No code changes are needed in `app_main`; you do not need to
call `esp_wolfssl_register_stack()` explicitly.**

The only requirement is that the `esp-wolfssl` component must be part of your
build so that the auto-registration init function gets linked in. The
recommended way to do that is via the IDF Component Manager:

```bash
# From the root of your project (the directory that contains main/):
idf.py add-dependency "espressif/esp-wolfssl^1.0.0"
```

This creates (or updates) `main/idf_component.yml` with an entry like:

```yaml
dependencies:
  espressif/esp-wolfssl: "^1.0.0"
```

The Component Manager then injects `esp-wolfssl` into `main`'s private
requirements before the build's dependency tree is expanded, so the component
is pulled in even under `MINIMAL_BUILD` projects without any further wiring.

Finally, enable the custom stack and (re)build:

```bash
idf.py menuconfig
#  → Component config
#     → ESP-TLS
#        → Choose SSL/TLS library for ESP-TLS … = (X) Custom TLS stack
idf.py build flash monitor
```

That's it — `esp-tls` calls now go through wolfSSL.

## Alternative: path-based dependency (in-tree / forks)

If you're working from a fork or vendor the component directly under
`components/esp-wolfssl/` in your project (e.g. while iterating on changes to
this repository), use a path-based dependency instead of the registry one. In
`main/idf_component.yml`:

```yaml
dependencies:
  esp-wolfssl:
    path: ${PROJECT_DIR}/components/esp-wolfssl
```

The auto-registration mechanism is the same; only the way the component is
located on disk differs.

## Verifying

On boot, `esp-tls` logs a single line confirming that the wolfSSL stack
registered successfully:

```
I (xxx) esp-tls-custom-stack: Custom TLS stack registered successfully
```

If you do not see that line and `esp_tls_conn_*` calls return
`ESP_ERR_INVALID_STATE` / "No TLS stack registered", the `esp-wolfssl`
component was likely trimmed out of the build — double-check that
`main/idf_component.yml` lists `esp-wolfssl` (registry or path) as a
dependency.

# Options (Debugging and more)
- `esp-wolfssl` esp-tls related options can be obtained by choosing SSL library as `wolfSSL` in `idf.py/make menuconfig -> Component Config -> ESP-TLS -> choose SSL Library `.
It shows following options

    - Enable SMALL_CERT_VERIFY
        - This is a flag used in wolfSSL component and is enabled by default in `esp-wolfssl`.
        - Enabling this flag allows user to authenticate the server by providing the Intermediate CA certificate of the server, for a more strict check disable this flag after which you will have to provide the root certificate at top of the hierarchy of certificate chain which will have `Common Name = Issuer Name`, Such a strict check is not compulsary in most cases hence by default the flag is enabled but the option is provided for the user.

    - Enable Debug Logs for wolfSSL
        - This option prints detailed logs of all the internal operations, highly useful when debugging an error.

- `esp-wolfssl` specific options (see NOTE) are available under `idf.py/make menuconfig -> Component Config -> wolfSSL`.

    - Enable ALPN ( Application Layer Protocol Negotiation ) in wolfSSL
        - This option is enabled by default for wolfSSL, and can be disabled if not required.

    - Enable OCSP (Online Certificate Status Protocol) in wolfSSL
        - This options is disabled by default. Enabling it adds support for checking the host's certificate revocation status
          during the TLS handshake.
---
**NOTE**
 These options are valid for `esp-tls` only if `wolfSSL` is selected as its SSL/TLS Library.
---
# Comparison of wolfSSL and mbedTLS

The following table shows a typical comparison between wolfSSL and mbedtls when `https_request` (which has server authentication) was run with both
SSL/TLS libraries and with all respective configurations set to default.
_(mbedtls IN_CONTENT length and OUT_CONTENT length were set to 16384 bytes and 4096 bytes respectively)_

| Property | wolfSSL | mbedTLS |
|--------------------|----------|----------|
| Total Heap Consumed| ~19 Kb | ~37 Kb |
| Task Stack Used | ~2.2 Kb | ~3.6 Kb |
| Bin size | ~858 Kb | ~736 Kb |

# Additional Pointers

In general, these are links which will be useful for using both wolfSSL, as well as networked and secure applications in general. Furthermore, there is a more comprehensive tutorial that can be found in Chapter 11 of the official wolfSSL manual. The examples in the wolfSSL package and Chapter 11 do appropriate error checking, which is worth taking a look at. For a more comprehensive API, check out chapter 17 of the official manual.

- wolfSSL Manual [https://www.wolfssl.com/docs/wolfssl-manual/]()
- wolfSSL GitHub
 [https://github.com/wolfssl/wolfssl]()

