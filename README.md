# AVSystem Commons Library

A set of common code used in [AVSystem](http://www.avsystem.com/) for projects written in C.

Currently the included components are:

 * Data structures
   * `avs_buffer` - simple data buffer with circular-like semantics
   * `avs_list` - lightweight, generic and type-safe implementation of a singly linked list, with API optimized for ad-hoc usage
   * `avs_rbtree` - basic implementation of a red-black binary search tree
   * `avs_vector` - generic implementation of a C++-style vector (dynamic array)
 * Networking framework
   * `avs_http` - minimal implementation of a [Hypertext Transfer Protocol (HTTP)](https://tools.ietf.org/html/rfc7230) client
   * `avs_net` - abstraction layer for TCP, UDP, SSL/TLS and DTLS network sockets, as well as DNS resolution and URL parsing
   * **NOTE:** `avs_commons` versions up to 4.0.x included an `avs_coap` module. This has been removed in favor of the [new CoAP implementation](https://github.com/AVSystem/Anjay/tree/master/deps/avs_coap) distributed as part of [Anjay](https://github.com/AVSystem/Anjay)
 * Other modules
   * `avs_algorithm` - currently contains a base64 encoder and decoder
   * `avs_log` - simple logging framework
   * `avs_stream` - generic framework for I/O streams; includes pre-implemented streams that can be used through its unified API:
     * `md5.h` - calculating MD5 hashes
     * `netbuf.h` - buffered network I/O
     * `stream_file.h` - file I/O
     * `stream_inbuf.h` - read-only wrapper for raw memory buffers
     * `stream_membuf.h` - in-memory stream optimized for a single-message write-then-read cycle
     * `stream_outbuf.h` - write-only wrapper for raw memory buffers
   * `avs_unit` - simple and easy to use unit testing framework
   * `avs_utils` - currently contains utility function for handling time values, psudorandom number generation and string tokenization

Most of the library is written in standard and portable C99. There are some dependencies on POSIX APIs, but there are provisions for replacing them when necessary (see the `compat` directory for details).

`avs_unit` relies on some GCC-isms and is unlikely to work with any compiler that is not based on either GCC or Clang.

The code is available under [Apache 2.0 License](LICENSE).

## Building

### Building using CMake

The preferred way of building `avs_commons` is to use CMake:

```sh
cmake . &&
make &&
make install
```

You may use `cmake -LH` or tools such as `cmake-gui` or `ccmake` to examine the available configuration options.

### Alternative build systems

Alternatively, you may use any other build system. You will need to:

 * Prepare your `avs_commons_config.h` file. See the comments in [`avs_commons_config.h.in`](include_public/avsystem/commons/avs_commons_config.h.in) for details.
 * Configure your build system so that:
   * At least all `*.c` and `*.h` files from `src` and `include_public` directories are preserved, with the directory structure intact.
   * All `*.c` files inside `src` or any of its direct or indirect subdirectories are compiled.
   * `src` and `include_public` directories are included in the header search path when compiling `avs_commons`.
   * `include_public` directory or a copy of it is included in the header search path when compiling dependent application code.

An example simplistic build process for a Unix-like shell could be:

```sh
# configuration
cp include_public/avsystem/commons/avs_commons_config.h.in include_public/avsystem/commons/avs_commons_config.h
vi include_public/avsystem/commons/avs_commons_config.h  # manually configure the library here

# compilation
cc -Iinclude_public -Isrc -c $(find src -name '*.c')
ar rcs libavs_commons.a *.o

# installation
cp libavs_commons.a /usr/local/lib/
cp -r include_public/avsystem /usr/local/include/
```

## Contact, contributing

 * Your feedback is important! Feel free to create an Issue here on GitHub.
 * If you would like to contribute to avs_commons just send us a pull request.
