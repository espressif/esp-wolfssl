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
 - To use `esp-wolfssl` as the esp-tls custom TLS stack (recommended, see below), ESP-IDF v6.x or later (master) is required — `CONFIG_ESP_TLS_CUSTOM_STACK` is not available in earlier releases.
 - To use the wolfSSL native APIs directly (as in `examples/wolfssl_client`), ESP-IDF v4.1 or later is sufficient.
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

# Using esp-wolfssl as a custom esp-tls stack (ESP-IDF 6.x)

From ESP-IDF 6.x onwards, `esp-tls` supports pluggable TLS backends via
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

> Note: until this version of the component is published to the
> [IDF Component Registry](https://components.espressif.com), use the
> path-based dependency described below instead.

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
- `esp-wolfssl` options are available under `idf.py menuconfig -> Component Config -> wolfSSL`.

    - Enable ALPN ( Application Layer Protocol Negotiation ) in wolfSSL
        - This option is enabled by default for wolfSSL, and can be disabled if not required.

    - Enable OCSP (Online Certificate Status Protocol) in wolfSSL
        - This options is disabled by default. Enabling it adds support for checking the host's certificate revocation status
          during the TLS handshake.

    - Enable Post-Quantum Cryptography (ML-KEM, ML-DSA, SHA-3/SHAKE)
        - Disabled by default. Enabling it compiles in the native wolfSSL PQC implementations
          (~30 kB of additional flash even when no PQC algorithm is used at runtime).

- Compile-time tuning (cipher suites, TLS 1.3, debug logging via `DEBUG_WOLFSSL`, etc.) is done in
  [port/user_settings.h](port/user_settings.h). Note that certificate chains are verified with
  `WOLFSSL_ALT_CERT_CHAINS`, i.e. providing the root CA is sufficient even when the server sends
  intermediates that are not in your trust store.

- Certificate date (notBefore/notAfter) validation is **enabled**: the system clock must be set
  (e.g. via SNTP, see the `https_request` example) before TLS connections are made, otherwise
  the handshake fails with a certificate-date error.
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

