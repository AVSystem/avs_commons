AVSystem Commons Library
========================

A set of common code used in [AVSystem](http://www.avsystem.com/) for projects written in C.

Currently the included components are:

 * `avs_buffer` - a simple data buffer with circular-like semantics
 * `avs_list` - a lightweight, generic and type-safe implementation of a singly linked list
 * `avs_unit` - a simple and easy to use unit testing framework

`avs_buffer` and `avs_list` are written in standard and portable C90. `avs_unit` relies on some GCC-isms.

The code is available under the permissive [MIT License](LICENSE).

avs_buffer
----------

A cute little buffer that you can read from and write to, as well as pass to library functions!

```c
#include <stdio.h>
#include <string.h>
#include <avsystem/commons/buffer.h>

int main() {
    avs_buffer_t *buffer;
    avs_buffer_create(&buffer, 1024);

    /* append immediate data */
    avs_buffer_append_bytes(buffer, "Hello! ", 7);

    /* pass to library function */
    const char *read_data =
            fgets(avs_buffer_raw_insert_ptr(buffer),
                  avs_buffer_space_left(buffer),
                  stdin);
    avs_buffer_advance_ptr(buffer, strlen(read_data));

    while (avs_buffer_data_size(buffer) > 0) {
        size_t printed_bytes =
                fwrite(avs_buffer_data(buffer), 1,
                       avs_buffer_data_size(buffer),
                       stdout);
        avs_buffer_consume_bytes(buffer, printed_bytes);
    }

    avs_buffer_free(&buffer);
}
```

avs_list
--------

Using a linked list of some arbitrary type in C was never as easy!

```c
#define _GNU_SOURCE /* for asprintf() */
#include <stdio.h>
#include <avsystem/commons/list.h>

typedef struct {
    int index;
    char *string;
} my_struct_t;

int main() {
    /* declare a list - just like that! */
    AVS_LIST(my_struct_t) list = NULL;

    /* let's fill it! */
    AVS_LIST(my_struct_t) *last_element = &list;
    for (int i = 0; i < 10; ++i) {
        /* create a new list element */
        *last_element = AVS_LIST_NEW_ELEMENT(my_struct_t);
        (*last_element)->index = i;
        asprintf(&(*last_element)->string, "This is list element %d", i);

        /* next element will be added after it */
        last_element = &AVS_LIST_NEXT(*last_element);
    }

    /* print the contents */
    my_struct_t *element;
    AVS_LIST_FOREACH(element, list) {
        printf("%d -- %s\n", element->index, element->string);
    }

    /* now free everything */
    AVS_LIST_CLEAR(&list) {
        free(list->string);
    }
}
```

There are other great features, such as another flavor of `FOREACH` that allows deleting elements on the go, pre-implemented sort and some more! See the documentation to `list.h` for more information and examples.

avs_unit
--------

Writing unit tests for your C code? We have some great tools for you!

```c
/*** file_under_test.c ***/

int square(int arg) {
    return arg * arg;
}

void uppercase(char *input) {
    for (; input && *input; ++input) {
        if (*input >= 'a' && *input < 'z') { /* <-- bug! :-E */
            *input += 'A' - 'a';
        }
    }
}

#ifdef UNIT_TESTING
#include "test_file.c"
#endif
```

```c
/*** test_file.c ***/
#include <avsystem/commons/unit/test.h>

AVS_UNIT_TEST(square, small_numbers) {
    AVS_UNIT_ASSERT_EQUAL(square(2), 4);
    AVS_UNIT_ASSERT_EQUAL(square(5), 25);
}

AVS_UNIT_TEST(uppercase, hello) {
    char input[] = "Hello, world123!";
    uppercase(input);
    AVS_UNIT_ASSERT_EQUAL_STRING(input, "HELLO, WORLD123!");
}

AVS_UNIT_TEST(uppercase, zanzibar) {
    char input[] = "Zanzibar";
    uppercase(input);
    AVS_UNIT_ASSERT_EQUAL_STRING(input, "ZANZIBAR");
}
```

Now just let the library do the magic:

```
$ cc -DUNIT_TESTING file_under_test.c -lavs_unit -lavs_list -o test
$ ./test
square                                                           1/1
[test_file.c:18] expected <ZANZIBAR> was <ZANzIBAR>
    zanzibar                                                     FAIL
uppercase                                                        1/2
```

See the Doxygen-generated documentation to learn about more features, such as function mocking!

Contact, contributing
---------------------

 * Your feedback is important! Feel free to create an Issue here on GitHub.
 * If you would like to contribute to avs_commons just send us a pull request.
