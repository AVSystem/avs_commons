AVSystem Commons Library
========================

A set of common code used in [AVSystem](http://www.avsystem.com/) for projects written in C.

Currently the included components are:

 * Data structures
   * `avs_buffer` - simple data buffer with circular-like semantics
   * `avs_list` - lightweight, generic and type-safe implementation of a singly linked list, with API optimized for ad-hoc usage
   * `avs_rbtree` - basic implementation of a red-black binary search tree
   * `avs_vector` - generic implementation of a C++-style vector (dynamic array)
 * Networking framework
   * `avs_coap` - implementation of the [Constrained Application Protocol (CoAP)](https://tools.ietf.org/html/rfc7252)
   * `avs_http` - minimal implementation of a [Hypertext Transfer Protocol (HTTP)](https://tools.ietf.org/html/rfc7230) client
   * `avs_net` - abstraction layer for TCP, UDP, SSL/TLS and DTLS network sockets, as well as DNS resolution and URL parsing
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

Contact, contributing
---------------------

 * Your feedback is important! Feel free to create an Issue here on GitHub.
 * If you would like to contribute to avs_commons just send us a pull request.
