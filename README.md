AVSystem Commons Library
========================

A set of common code used in [AVSystem](http://www.avsystem.com/) for projects written in C.

Currently the included components are:

 * `avs_buffer` - a simple data buffer with circular-like semantics
 * `avs_list` - a lightweight, generic and type-safe implementation of a singly linked list
 * `avs_unit` - a simple and easy to use unit testing framework

`avs_buffer` and `avs_list` are written in standard and portable C90. `avs_unit` relies on some GCC-isms.

The code is available under [Apache 2.0 License](LICENSE).

avs_buffer
----------

A cute little buffer that you can read from and write to, as well as pass to library functions!

avs_list
--------

Using a linked list of some arbitrary type in C was never as easy!

There are other great features, such as another flavor of `FOREACH` that allows deleting elements on the go, pre-implemented sort and some more! See the documentation to `list.h` for more information and examples.

avs_unit
--------

Writing unit tests for your C code? We have some great tools for you!

See the Doxygen-generated documentation to learn about more features, such as function mocking!

Contact, contributing
---------------------

 * Your feedback is important! Feel free to create an Issue here on GitHub.
 * If you would like to contribute to avs_commons just send us a pull request.
