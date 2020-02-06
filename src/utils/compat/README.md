# Custom time functions
When not using the implementation written for POSIX-compatible and POSIX-like
operating systems (`WITH_POSIX_AVS_TIME=OFF`), the following functions need to be
implemented:

- `avs_time_real_t avs_time_real_now(void);`

- `avs_time_monotonic_t avs_time_monotonic_now(void);`

# Custom allocator
When not using the default implementation of C memory allocator (i.e. `WITH_STANDARD_ALLOCATOR=OFF`),
the following functions need to be implemented:

- `void *avs_malloc(size_t size)`

- `void avs_free(void *ptr);`

- `void *avs_calloc(size_t nmemb, size_t size);`

- `void *avs_realloc(void *ptr, size_t size);`
