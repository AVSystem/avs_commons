When not using the implementation written for POSIX-compatible and POSIX-like
operating systems (WITH_POSIX_AVS_TIME=OFF), the following functions need to be
implemented:

avs_time_real_t avs_time_real_now(void);

avs_time_monotonic_t avs_time_monotonic_now(void);
