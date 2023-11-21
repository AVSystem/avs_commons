# Changelog

## avs_commons 5.4.2 (November 21st, 2023)

### Features

* Refactored the PRNG integration in the Mbed TLS backend so that the PSA RNG
  API can be used if CTR-DRBG and/or entropy APIs are disabled

### Bugfixes

* Additional validation in ``avs_persistence_string()`` to avoid restoring a
  string with superfluous data after the nullbyte

## avs_commons 5.4.1 (October 9th, 2023)

### Bugfixes

* Fixes in CMake scripts when searching for mbed TLS in the case when
  ``MBEDTLS_ROOT_DIR``, ``CMAKE_FIND_ROOT_PATH`` and
  ``CMAKE_FIND_ROOT_PATH_MODE_*`` are all specified explicitly
* Fixes in some ``#ifdef`` directives that caused compilation failures when
  ``AVS_COMMONS_WITH_AVS_CRYPTO_PSK`` was disabled

## avs_commons 5.4.0 (September 7th, 2023)

### BREAKING CHANGES

* Default POSIX socket implementation now doesn't include ``errno.h`` if
  definition of ``EDOM`` (available by e.g. including lwIP's ``lwip/errno.h``)
  is included in ``AVS_COMMONS_POSIX_COMPAT_HEADER``.

### Improvements

* Made MD5 length define publicly visible (for easier avs_stream_md5 usage)
* Made (D)TLS session resumption and persistence possible on Mbed TLS 3.0+ even
  when MBEDTLS_SSL_SRV_C is disabled

### Bugfixes

* Added missing null guards in (D)TLS socket implementations so that all methods
  are now safe to call in any state
* When using lwIP, default POSIX socket implementation and appropriate compat
  header now include lwIP's ``lwip/errno.h`` instead of system ``errno.h``

## avs_commons 5.3.1 (June 12th, 2023)

### Features

* Added ``AVS_NET_SOCKET_OPT_PREFERRED_ADDR_FAMILY`` and
  ``AVS_NET_SOCKET_OPT_FORCED_ADDR_FAMILY`` options that allow setting address
  family configuration of an already created socket
* Automatically upgrading IPv4 sockets to IPv6 when connecting is now possible
* Added ``AVS_UNIT_MOCK_DECLARE()`` and ``AVS_UNIT_MOCK_DEFINE()`` to facilitate
  declaring mocked functions with external linkage

### Improvements

* Slightly changed the semantics of ``avs_sched_run()``, to fix erroneous
  behavior on platforms with low-resolution system clocks

## avs_commons 5.3.0 (March 10th, 2023)

### Features

* Added the ``AVS_COMMONS_NET_POSIX_AVS_SOCKET_WITHOUT_IN6_V4MAPPED_SUPPORT``
  configuration option that improves dual-stack IPv4+IPv6 connectivity on
  platforms that do not support IPv4-mapped IPv6 addresses (``::ffff:0:0/96``)

### Improvements

* Trivial fixes to silence warnings on certain commercial compilers
  (contributed by Flonidan A/S)
* Removed usages of most deprecated Mbed TLS and OpenSSL APIs

## avs_commons 5.2.0 (February 20th, 2023)

### BREAKING CHANGES

* Removed ``avs_unit_memstream`` that is now unused

### Features

* Added persistence of DTLS context state related to the Connection ID extension
  and the related ``AVS_NET_SOCKET_OPT_CONNECTION_ID_RESUMED`` option
* Added option to set avs_log logging level in compile time. If
  `AVS_COMMONS_WITH_EXTERNAL_LOG_LEVELS_HEADER` is specified, inactive logs will
  be removed during compile time
* Added option to disable log level check in runtime, if active the macros
  `avs_log_set_level` and `avs_log_set_default_level` are not available

### Improvements

* Avoid calling ``avs_net_socket_send()`` with zero-length buffers when using
  ``avs_stream_netbuf``

### Bugfixes

* Fixed ``out_message_finished`` and ``out_bytes_read`` not being set when
  ``read`` is called with a NULL buffer in ``avs_stream_inbuf``

## avs_commons 5.1.3 (December 7th, 2022)

### Improvements

* Added support for setting MTU in the Mbed TLS backend
* Added the "alignfix" alternate memory allocator

### Bugfixes

* Fixed tls session persistence flag
* Removed calling mbedtls_ssl_ciphersuite_uses_psk() if PSK is disabled in
  Mbed TLS

## avs_commons 5.1.2 (August 24th, 2022)

### Bugfixes

* Fixed definition and usages of avs_realloc()

## avs_commons 5.1.1 (July 22nd, 2022)

### Improvements

* Improved compatibility with older versions of Mbed TLS

## avs_commons 5.1.0 (July 6th, 2022)

### Features

* Support for TLS 1.3 using the OpenSSL and Mbed TLS backends, as well as for
  DTLS 1.3 using the Mbed TLS backend (if built against a TLS library version
  that supports it)
* Added new AVS_SORTED_SET API which mirrors AVS_RBTREE, but can be implemented
  either using AVS_RBTREE (better complexity, but bigger code) or AVS_LIST
  (slower, but smaller code)
* DTLS handshake timeouts can now be changed for existing sockets using the
  avs_net_socket_set_opt() function

### Bugfixes

* Fixed compilation of Mbed TLS-based variant of avs_net if MBEDTLS_PK_WRITE_C
  is disabled

## avs_commons 5.0.0 (May 18th, 2022)

### BREAKING CHANGES

* Removed the old avs_net_psk_info_t API and renamed avs_net_generic_psk_info_t
  to avs_net_psk_info_t

### Features

* New AVS_NET_SOCKET_HAS_BUFFERED_DATA socket option that allows for checking
  internal socket buffer state in a more robust way
* Added support for OpenSSL 3

### Bugfixes

* Fixed some CMake warnings

## avs_commons 4.10.0 (April 8th, 2022)

### BREAKING CHANGES

* New API for PSK security credentials, unified with
  avs_crypto_security_info_union_t

### Features

* Added support for Mbed TLS 3.1
* Added support for using PSK security credentials through hardware security
  engines
* Added API for uploading software-based private keys onto hardware security
  engines

### Improvements

* Added a AVS_COMMONS_WITHOUT_TLS macro public for easier checking of (D)TLS
  support
* Stopped using LOG macro in expression context for better compatibility with
  external logger implementations
* Lowered log level of the "scheduler already shut down" as that is not really
  a fatal condition

### Bugfixes

* Failure to load DANE credentials if DANE is enforced is now properly a fatal
  error in OpenSSL backend
* Fixed support for PEM-formatted certificates and CRLs in Mbed TLS backend

## avs_commons 4.9.1 (November 29th, 2021)

### Improvements

* optimized avs_match_token() function
  (https://github.com/AVSystem/avs_commons/pull/308),
* optimized avs_url_percent_decode() function
  (https://github.com/AVSystem/avs_commons/pull/306),
* use the default PRNG when custom TLS is used.

### Bugfixes

* prevent using unchecked `__GNUC__` macro.

## avs_commons 4.9.0 (October 1st, 2021)

### Features

* Support for completely replacing the avs_log implementation
* Better support for integrating with custom TLS compatibility layers
* (commercial version only) Support for PSA API for hardware-based security

### Improvements

* Added support for Mbed TLS 3.0

### Bugfixes

* Fixed compatibility some platforms, including ESP-IDF and MinGW (winpthreads)

## avs_commons 4.8.1 (July 19th, 2021)

### Features

* Added support for MBEDTLS_SSL_KEEP_PEER_CERTIFICATE flag in Mbed TLS 2.17

### Bugfixes

* Fixed call to avs_hexlify() in connection ID handling in avs_mbedtls_socket

## avs_commons 4.8.0 (June 29th, 2021)

### Features

* Added extended log handler API, it allows creation of log handlers with
  custom message format including module, file and line number parameters.

### Improvements

* Handle case where PKCS#11 implementation uses null-terminated strings
  against the specification. (commercial version only)

## avs_commons 4.7.2 (June 2nd, 2021)

### Improvements

* When using custom ciphersuite settings, they are now properly filtered
  according to the security mode in use (PSK vs. certificates) in all backends
* Made avs_compat_pthread preferred over avs_compat_atomic_spinlock when both
  are enabled

## avs_commons 4.7.1 (April 29th, 2021)

### Improvements

* Added suppressions for memory leaks originating from OpenSSL and libp11 when
  running under LeakSanitizer (relevant mostly for commercial version)
* (commercial version only) Fixed a compilation warning in PKCS#11 integration

### Bugfixes

* Added missing #ifdefs to avs_stream_common.c, that prevented compilation when
  avs_stream component was disabled (contributed by https://github.com/anuar2k)
* Fixed implementations of avs_stream_read_t that did not handle NULL output
  pointers properly - this fixes some potential crashes in the HTTP client

## avs_commons 4.7.0 (March 19th, 2021)

### Features

* Rewritten PKCS#11-based hardware security support; the new version is
  included only in commercial version, includes support for both OpenSSL and
  Mbed TLS backends, and uses ECDSA for key generation in both backends
  (the OpenSSL version previously generated RSA keys)

### Improvements

* Made some linting checks (visibility, header and code duplication
  verification) more generic so that the code can be reused by other projects

### Bugfixes

* Fixed a problem with compiling the Mbed TLS backend when
  AVS_COMMONS_WITH_AVS_CRYPTO_PKI or WITH_DANE_SUPPORT is disabled
* Fixed logic of detecting cryptographic file formats, which prevented
  PEM files with comments from being loaded
* Added some missing NULL checks in atomic spinlock-based threading backend and
  Mbed TLS crypto backend

## avs_commons 4.6.0 (January 11th, 2021)

### BREAKING CHANGES

* Refactored avs_net_local_address_for_target_host() in a way that may be
  breaking for users who maintain their own socket integration code

### Improvements

* Additional tests for the avs_stream module

### Bugfixes

* Fixed erroneous bounds check in _avs_crypto_get_data_source_definition()
* Made removal of PKCS#11 objects more resilient to errors (relevant mostly for
  commercial Anjay users)
* Fixed CMake code for importing the libp11 library (relevant mostly for
  commercial Anjay users)

## avs_commons 4.5.0 (November 23rd, 2020)

### BREAKING CHANGES

* Moved URL handling routines to a separate avs_url component
* Implementation of avs_net_validate_ip_address() is no longer required when
  writing custom socket integration layer
* Hardware Security Module support has been reorganized to allow easier
  implementation of third-party engines

### Features

* Support for private key generation and removal on Hardware Security Modules
  via PKCS#11 engine
* Support for storing and removing certificates stored on Hardware Security
  Modules via PKCS#11 engine
* Support for certificate chain reconstruction based on trust store when
  performing (D)TLS handshake
* New AVS_DOUBLE_AS_STRING() API and AVS_COMMONS_WITHOUT_FLOAT_FORMAT_SPECIFIERS
  configuration options, making it possible to stringify floating point numbers
  on libc implementations that don't support printf("%g")

### Improvements

* Simplified URL hostname validation - it is now somewhat more lenient, but no
  longer depends on avs_net_validate_ip_address()
* Removed internal usage of avs_net_validate_ip_address() and reimplemented it
  as an inline function that wraps avs_net_addrinfo_resolve_ex()
* Better CMake-level dependencies and compile-time error handling for
  compile-time configuration options
* PEM-formatted security objects can now be loaded from buffer in the Mbed TLS
  backend

### Bugfixes

* Fixed conditional compilation clauses for avs_crypto global initialization
* Additional NULL checks when loading security information
* Removed duplicate file names that could prevent building with some embedded
  IDEs

## avs_commons 4.4.0 (October 6th, 2020)

### BREAKING CHANGES

* Significant refactor of avs_crypto_security_info_union_t family of types
  (compatibility aliases are available)

### Features

* Initial support for PKCS11-based hardware security
* New APIs:
  * avs_crypto_certificate_chain_info_array_persistence()
  * avs_crypto_certificate_chain_info_from_engine()
  * avs_crypto_certificate_chain_info_list_persistence()
  * avs_crypto_certificate_chain_info_persist()
  * avs_crypto_cert_revocation_list_info_array_persistence()
  * avs_crypto_cert_revocation_list_info_list_persistence()
  * avs_crypto_cert_revocation_list_info_persist()
  * avs_crypto_private_key_info_copy()
  * avs_crypto_private_key_info_from_engine()
  * avs_crypto_private_key_info_persistence()
  * avs_net_socket_dane_tlsa_array_copy()
  * avs_stream_copy()
  * avs_stream_offset()
* Added scripts simplifying unit test code coverage calculation

## avs_commons 4.3.1 (August 31st, 2020)

### Improvements

* Replaced the test PKCS#7 file in unit tests with a more modern one, that can
  be loaded properly with newest releases of Mbed TLS

### Bugfixes

* Made the library compile again with Mbed TLS configured without CRL support
  or without file system support
* Fixed some testing code to make it work on macOS and Raspberry Pi OS again
* Added __odr_asan to the list of permitted symbols so that "make check"
  succeeds when the library is built with AddressSanitizer enabled

## avs_commons 4.3.0 (August 24th, 2020)

### Features

* Improved trust store handling, including:
  * Support for configuring usage of system-wide trust store
  * Support for trusted certificate arrays and lists in addition to single
    entries
  * Support for CRLs
* Support for DANE TLSA entries
* Support for loading certs-only PKCS#7 files
* New avs_crypto_client_cert_expiration_date() API
* Removed dtls_echo_server tool that has been unused since version 4.1

### Bugfixes

* Fixed a bug that prevented compiling avs_commons without TLS support
* Fixed missing error handling in avs_persistence_sized_buffer()
* Fixed a bug in safe_add_int64_t() that could cause a crash if the result of
  addition was INT64_MIN
* Fixed various compilation warnings

## avs_commons 4.2.1 (July 7th, 2020)

### Bugfixes

* Further fixed problems with installing the library via CMake
* Fixed various missing ``#include``s and CMake settings

## avs_commons 4.2.0 (July 1st, 2020)

### Features

* Added ``avs_crypto_pki_csr_create()``
* Made ``WITH_AVS_CRYPTO_ADVANCED_FEATURES`` a configurable CMake option instead
  of relying on autodetection alone

### Improvements

* ``avs_net_socket_receive_from()`` can now be called with the source address
  argument set to NULL
* Moved certificate and key handling to avs_crypto and made it a dependency of
  avs_net

### Bugfixes

* Fixed problems with using installed library due to aliased CMake target names

## avs_commons 4.1.3 (May 28th, 2020)

### Bugfixes

* Fixes in CMake scripts for corner cases when searching for mbed TLS
* Fix for allowing compilation on platforms that define macros that conflict
  with avs_log verbosity levels (DEBUG, ERROR etc.)

## avs_commons 4.1.2 (May 22nd, 2020)

### Bugfixes

* Fixed interoperability problem with CMake versions older than 3.11

## avs_commons 4.1.1 (May 21st, 2020)

### Bugfixes

* Fixed a bug in CMake scripts that caused link errors when using statically
  linked versions of mbed TLS

## avs_commons 4.1.0 (April 23rd, 2020)

### BREAKING CHANGES

* Renamed public header files for better uniqueness
* Redesigned socket creation and in-place decoration APIs, including the
  addition of a requirement to provide PRNG context
* Renamed some public configuration macros, to unify with the updated
  compile-time configuration pattern
* Removed the legacy avs_coap component (the version used by Anjay 1.x)
* Removed the mbed TLS custom entropy initializer pattern in favor of the new
  PRNG framework

### Features

* Building without CMake is now officially supported
* Added idiomatic C++ wrapper for AVS_LIST
* New API for cryptographically safe PRNGs in avs_crypto
* File-based streams and default log handler can now be disabled at compile time

### Bugfixes

* Fixed a bug in the default socket implementation that prevented compiling on
  platforms without the IP_TOS socket option support
* Fixed improper parsing of empty host in URLs
* Some previously missed log messages now properly respect WITH_AVS_MICRO_LOGS
* Fixed a bug in netbuf stream's error handling

## avs_commons 4.0.3 (February 7th, 2020)

### Bugfixes

* Fix for scope of avs_net_mbedtls_entropy_init() declaration in deps.h
* Fix that prevented net_impl.c from compiling when IP_TOS is not available

## avs_commons 4.0.2 (January 28th, 2020)

### Features

* Support for proper RFC 6125-compliant validation of certificates against
  hostnames in the OpenSSL backend

### Bugfixes

* Fix to TLS backend data loader unit tests

## avs_commons 4.0.1 (December 20th, 2019)

### Bugfixes

* Prevented certificate-based ciphersuites from being sent in Client Hello when
  PSK is used over the OpenSSL backend

### Features

* Introduced "micro log" feature and AVS_DISPOSABLE_LOG() macro

## avs_commons 4.0.0 (November 28th, 2019)

### BREAKING CHANGES

* Refactored error handling, introducing the new avs_error_t concept
* Renamed avs_stream_abstract_t to avs_stream_t
* Renamed avs_net_abstract_socket_t to avs_net_socket_t

### Features

* avs_net
  * Added support for Server Name Identification (D)TLS extension when using
    OpenSSL, and ability to enable or disable it explicitly
  * Added support for DTLS Connection ID extension if using a development version
    of mbed TLS that supports it
  * Added possibility to use custom mbed TLS entropy pool configuration
  * Added ability to configure (D)TLS ciphersuites
  * Added propagation of (D)TLS handshake alert codes to user code
  * Implemented accept() call for UDP sockets
  * Added avs_url_parse_lenient function and separate validation functions
* avs_stream
  * Added avs_stream_membuf_take_ownership function
  * Added avs_stream_membuf_reserve function
* avs_utils
  * Added avs_unhexlify function
* avs_algorithm
  * Refactored base64 to support alternate alphabets and padding settings
* avs_unit
  * Added support for and_then callbacks in mock sockets

### Improvements

* Made logs render "..." at the end if truncated
* Improved compatibility with various platforms, including Zephyr
* Improved structure of CMake stage configuration, removed unused definitions
* Reformatted entire codebase

### Bugfixes

* Fixed some improperly propagated error cases in HTTP client
* Fixed problems with avs_net sockets not working for localhost if no
  non-loopback network interfaces are available
* Fixed some potential NULL dereferences, assertion errors and various other
  fixes

## avs_commons 3.11.0 (October 1st, 2019)

**NOTE:** avs_commons 3.11 is a one-off release that backported some avs_commons
4.0 features onto the 3.10.1 branch. It does **not** include all changes from
avs_commons 3.10.2.

### Features

* Added DTLS session resumption and handshake timeouts support in the OpenSSL
  backend

## avs_commons 3.10.2 (July 2nd, 2019)

### BREAKING CHANGES

* Removed ignoring context feature from avs_persistence

### Features

* Added support for Server Name Identification (SNI) TLS extension (available
  only in the Mbed TLS backend)
* Added avs_crypto module
* Added ``avs_persistence_magic()`` and ``avs_persistence_version()`` APIs
* Added support for SNI in the OpenSSL backend

### Improvements

* Added support for ``signed char`` in ``AVS_UNIT_ASSERT_EQUAL()``
* Sanitized dependencies between avs_commons modules
* Various compatibility improvements
* Added extern "C" clauses missing in some files, added regression testing for
  that, fixed some other C++ incompatibilities

### Bugfixes

* Added various missing NULL checks

## avs_commons 3.10.1 (April 30th, 2019)

### Bugfixes

* Fixed inconsisted include guard name in ``stream_membuf.h``

## avs_commons 3.10.0 (April 23rd, 2019)

### Features

* Made avs_persistence contexts stack-allocatable
* Added statistical counters in avs_net

### Bugfixes

* Fixed results of `avs_coap_exchange_lifetime()`. Previously the results were
  not in line with RFC7252 requirements, an order of magnitude off in some
  cases
* Various compatibility fixes

## avs_commons 3.9.1 (March 26th, 2019)

### Bugfixes

* Fix of usage of select() on platforms that do not support poll()
* Added new AVS_RESCHED_* APIs
* Fixes for various compilation warnings

## avs_commons 3.9.0 (February 14th, 2019)

### BREAKING CHANGES

* Extracted avs_stream_net library to break a dependency cycle between
  components. Applications that do not use CMake need to manually add
  libavs_stream_net.a to the linker command line.
* Various renames and refactors for better API consistency

### Features

* Added condition variables to compat_threading
* Added avs_sched
* Added avs_shared_buffer
* Added various utility APIs
* Added support for CoAP FETCH and iPATCH codes

### Improvements

* Further improved C++ compatibility
* Prevented http_close() from unnecessarily downloading the data to end

## avs_commons 3.8.3 (October 24th, 2018)

### Features

* Reimplemented ``avs_coap_opt_u*_value()`` and
  ``avs_coap_msg_get_option_u*()``; removed the ``_uint()`` variants

## avs_commons 3.8.2 (October 3rd, 2018)

### Improvements

* Improved logs from the IP address stringification code.

### Bugfixes

* Fixes for proper propagation of avs_stream_close() errors.
* Fixes for external library dependency checking.
* Fixes for various compilation warnings.

## avs_commons 3.8.1 (September 21st, 2018)

### Bugfixes

* Fixed include directory settings when custom compat_threading is used

## avs_commons 3.8.0 (September 13th, 2018)

### BREAKING CHANGES

* avs_commons now requires CMake 3.4.0 or higher.

## avs_commons 3.7.1 (September 4th, 2018)

### Bugfixes

* Fixed a problem that unit tests didn't compile with OpenSSL versions that do
  not support DTLS 1.2

## avs_commons 3.7.0 (August 27th, 2018)

### Features

* Added equality comparators for avs_time primitives
* Support for ``avs_net_socket_decorate()`` in more socket states
* Added ``avs_stream_simple_output_create()``,
  ``avs_stream_simple_input_create()`` and ``avs_stream_buffered_create()`` APIs

### Improvements

* Improved compatibility with various OSes, like Arch Linux

## avs_commons 3.6.2 (July 10th, 2018)

### Bugfixes

* a more restrictive approach to symbols from POSIX or C standard library
  that should not be used in embedded environments
* a fix of compilation on ARMCC
* a fix of compile time warning on IAR

## avs_commons 3.6.1 (June 29th, 2018)

### Bugfixes

* Fixed compatibility issues in tests.

## avs_commons 3.6.0 (June 28th, 2018)

### Features

* ``avs_compat_threading`` module, implementing necessary synchronization
  primitives used across AvsCommons such as mutexes
* ``avs_cleanup_global_state()`` method, allowing to (optionally) free any
  global state implicitly instantiated in avs_commons
* Support for previously missing functions in the mock socket in avs_unit

### Improvements

* Further compatibility fixes for FreeBSD

## avs_commons 3.5.0 (June 15th, 2018)

### BREAKING CHANGES

* Support for ``AVS_LIST_CONFIG_ALLOC`` and ``AVS_LIST_CONFIG_FREE`` has been
  removed in favour of the new library-wide allocator setting

### Features

* Added support for custom heap allocators (``avs_malloc``, ``avs_calloc``,
  ``avs_realloc``, ``avs_free``)

### Improvements

* removal of use of all ``time()`` calls,
* removal of use of variable length array language feature,
* default socket implementation refactor to use a nonblocking socket API,

## avs_commons 3.4.3 (May 29th, 2018)

### Features

* Added ``AVS_ASSERT()`` and ``AVS_UNREACHABLE()`` APIs

### Improvements

* Further improvements to handling of POSIX-compatibility headers

## avs_commons 3.4.2 (May 28th, 2018)

### BREAKING CHANGES

* Refactored global state management - if you are providing your own network
  stack integration, you will need provide two additional functions:
  `_avs_net_initialize_global_compat_state` and
  `_avs_net_cleanup_global_compat_state`

### Features

* New avs_list APIs: ``AVS_LIST_ADVANCE()``, ``AVS_LIST_ADVANCE_PTR()``
* Initial support for Windows

### Improvements

* Various compatibility improvements

## avs_commons 3.4.1 (May 17th, 2018)

### Bugfixes

- Fixed bug in avs_http that prevented digest authentication from working
- Fixed conditional compilation bugs in avs_net that made it impossible to
  disable certain features
- Fixed bugs in avs_net unit tests that prevented them from passing on systems
  without JDK installed and when ran as root

### Improvements

- Simplified TLS session persistence logic (removed dependency on mbed TLS
  session cache)
- Fixed compilation warnings on mbed TLS >= 2.7
- Worked around false positive warnings from scan-build 6.0

## avs_commons 3.4.0 (May 10th, 2018)

### Features

* Moved persistence subsystem from Anjay and improved upon it:
  * Added support for persisting additional integer types
  * Added support for persisting containers with variable size elements
  * Added ability to check the type of persistence context

### Improvements

* BREAKING API CHANGE: Changed TLS session resumption API so that it is now
  serialized to and deserialized from user-provided buffer
* BREAKING API CHANGE: Simplified certificate and key configuration API
  * Note that this change dropped support for some libraries that implement
    "fake" OpenSSL API
* Refactored avs_log() so that compiler will always parse TRACE-level logs, even
  if code generation for them is disabled
* Fixed various compilation warnings and compatibility with different compilers
* Fixed warnings when compiling with mbed TLS 2.3 and newer

### Bugfixes

* Fixed critical bugs in CoAP option handling:
  * Potential integer overflow
  * Erroneous operation on big-endian machines
* Added various missing NULL checks

## avs_commons 3.3.2 (March 9th, 2018)

### Features

* Added new ``avs_hexlify_some()`` API

### Bugfixes

* Added missing ``#include`` in the Mbed TLS backend

## avs_commons 3.3.1 (February 28th, 2018)

### Bugfixes

* Further fixes for C++ compatibility of avs_list
* Proper handling of message truncation in DTLS
* Allowed ACK_RANDOM_FACTOR equal to 1.0 in avs_coap

## avs_commons 3.3.0 (February 15th, 2018)

### Features

* Added ``WITH_X509`` configuration option to allow disabling certificate-based
  security support

### Improvements

* Improvements to interoperability with C++ code and various C compilers of
  macro-based data structures such as ``AVS_LIST()``

## avs_commons 3.2.5 (January 31st, 2018)

### Bugfixes

* Fix of the "preferred endpoint" feature, which prevented the CWMP requirement
  for ACS node affinity from working properly.
* Fixed problems that prevented binding sockets on ephemeral ports on some
  platforms (e.g. lwIP).
* Fixed problems that prevented SSL/TLS from working on platforms that don't
  support the atexit() function (mostly embedded environments).
* Fixed problems with linking Mbed libraries properly.

## avs_commons 3.2.4 (January 8th, 2018)

### Bugfixes

* Fixed sending the Cookie HTTP header (multiple cookies are sent in a single
  header) in line with the RFC requirements.

## avs_commons 3.2.3 (January 8th, 2018)

### Improvements

* Ran shellcheck on scripts within the project

## avs_commons 3.2.2 (December 18th, 2017)

### Improvements

* Unified errno handling across all modules

### Bugfixes

* Workaround for strict aliasing issues in avs_list

## avs_commons 3.2.1 (December 11th, 2017)

### Features

* Added possibility to disable unit tests even if avs_unit is being compiled

### Improvements

* Fixed interoperability with HTTP servers that unexpectedly close connection
* Various compatibility fixes for FreeBSD

### Bugfixes

* Fixed undefined behavior in CoAP message cache
* Fixed compatibility with compilers that don't support either stdatomic.h or
  GCC-style __sync_* builtins
* Prevented CoAP back-off timer randomization from occasionally using negative
  numbers
* Fixed minor error handling problems
* Fixed link commands for TinyDTLS interoperability

## avs_commons 3.2.0 (November 24th, 2017)

### Features

* Added new API: ``avs_http_set_header_storage()``

### Improvements

* Changed lifetime of Mbed TLS RNG structures to improve memory footprint

### Bugfixes

* Fixed error handling in avs_http
* Fixed erroneous random range handling in avs_coap
* Added support for URLs without path but with query string, and with tildes

## avs_commons 3.1.0 (October 5th, 2017)

### BREAKING CHANGES

* Refactored time handling, including separate data types for absolute and
  relative time values

### Improvements

* Further isolated compatibility with non-POSIX platforms

### Bugfixes

* Fixed TRACE logs not being compiled in some

## avs_commons 3.0.3 (September 19th, 2017)

### Improvements

* Made all source file names unique project-wide, to improve compatibility with
  some embedded IDEs

## avs_commons 3.0.2 (September 14th, 2017)

### Features

* Added ``preferred_family`` field in ``avs_net_socket_configuration_t`` and
  prevented the library from performing unnecessary DNS queries.
* Added option for detailed logging from the Mbed TLS backend

### Improvements

* Sanitized usages of GCC visibility pragmas
* Fixed support for platforms without ``CLOCK_MONOTONIC``

## avs_commons 3.0.1 (September 8th, 2017)

### Improvements

* Fixed compatibility with lwIP 2.0
* Improved compatibility with various operating systems including CentOS and
  macOS
* Improved compatibility with IAR Embedded Workbench
* Improved compatibility with platforms that do not have ``getifaddrs()``

### Bugfixes

* Fixed buffer overflow in msg_cache test in avs_coap
* Fixed handling of empty username/password in the HTTP client
* Fixed license_check make target in out-of-source builds

## avs_commons 3.0.0 (August 30th, 2017)

### BREAKING CHANGES

* Open source license of avs_commons changed from MIT to Apache 2.0
* Refactored the ``write`` method in avs_stream so that the vtable entry now may
  support short writes and is called ``write_some``
* Added ``avs_net_socket_get_local_host()`` method
* Removed support for short writes in ``avs_net_socket_send_to()``
* ``OPENSSL_CUSTOM_CIPHERS_ENABLED`` and ``WITH_OPENSSL_CUSTOM_CIPHERS`` CMake
  flags are no longer set by default. Use
  ``WITH_OPENSSL_CUSTOM_CIPHERS=DEFAULT:!ECDSA`` to restore previous defaults

### Features

* CoAP client component, based on code previously written for Anjay, has been
  added
* HTTP client component, based on code previously written for libCWMP, has been
  added
* Added URL parsing routines
* Added time handling routines
* Various new utility functions
* POSIX dependencies are now better isolated to ease porting onto non-POSIX
  platforms

### Bugfixes

* Fixed case where SSLv2_OR_3 is used in OpenSSL >= 1.1.0
* Fixed various possible compilation warnings
* Sanitized error handling for ``avs_net_socket_accept()``

## avs_commons 2.0.7 (July 24th, 2017)

### Features

* Made DTLS handshake timeout configurable

### Improvements

* Added CMake logic for properly finding the TinyDTLS library
* Minor refactors in PSK data ownership handling

### Bugfixes

* Fixed a typo in FindMbedTLS.cmake
* Fixed minor compilation warnings in the OpenSSL backend

## avs_commons 2.0.6 (July 12th, 2017)

### Features

* Added fallback implementation of ``rand_r()`` for systems that don't have one

### Improvements

* Changed asserts in avs_unit to use more natural comparisons
* Added extra casts to silence static analysis warnings
* Various improvements to mock socket implementation

### Bugfixes

* Fixed data type conversions in SSL integration
* Fixed a possible undefined behavior in AVS_RBTREE_SIMPLE_CLONE()
* Sanitized error checking in system_socket_net()

## avs_commons 2.0.5 (June 19th, 2017)

### Improvements

* Made AVS_LIST_MERGE and AVS_LIST_SORT stable
* Added possibility to specify default mocked MTU in avs_unit mock sockets

### Bugfixes

* Fixed Mbed TLS detection in out-of-source builds
* Fixed a problem that the library was not compiling with minimal flags
* Made sure that avs_buffer data is properly aligned
* Fixed a bug in AVS_ALIGN_POINTER_INTERNAL__

## avs_commons 2.0.4 (April 3rd, 2017)

### Improvements

* Made DTLS and PSK support state configurable, and disabled those by default
* Improved compatibility with different versions of OpenSSL

## avs_commons 2.0.3 (March 23rd, 2017)

### Bugfixes

* Fixed a bug in integration with mbed TLS which sometimes caused failures
  during receiving

## avs_commons 2.0.2 (March 14th, 2017)

### Bugfixes

* Fixed compatibility with OpenSSL 0.9.7

## avs_commons 2.0.1 (March 14th, 2017)

### Improvements

* Prevented calling SSL_shutdown after socket shutdown

## avs_commons 2.0.0 (March 8th, 2017)

### Features (partial list)

* Added base64 codec implementation
* Added logging subsystem
* Added networking subsystem, including SSL library integration
* Added red-black tree implementation
* Added streaming API
* Added vector implementation

## avs_commons 1.0.0 (February 13th, 2014)

Initial release.

**NOTE:** Before 2.0.0, avs_commons was a rolling release, and had no explicit
version numbers.
