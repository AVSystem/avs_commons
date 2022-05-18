/*
 * Copyright 2022 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef AVS_UNIT_TESTING
#    define _GNU_SOURCE // for timegm() in tests
#endif                  // AVS_UNIT_TESTING

#include <avs_commons_init.h>

#if defined(AVS_COMMONS_WITH_AVS_CRYPTO)                          \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) \
        && defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI)               \
        && defined(AVS_COMMONS_WITH_MBEDTLS)

#    define AVS_COMMONS_CRYPTO_MBEDTLS_PRIVATE_C

#    include "avs_mbedtls_private.h"

VISIBILITY_SOURCE_BEGIN

static int64_t year_to_days(int year, bool *out_is_leap) {
    // NOTE: Gregorian calendar rules are used proleptically here, which means
    // that dates before 1583 will not align with historical documents. Negative
    // dates handling might also be confusing (i.e. year == -1 means 2 BC).
    //
    // These rules are, however, consistent with the ISO 8601 convention that
    // ASN.1 GeneralizedTime type references, not to mention that X.509
    // certificates are generally not expected to contain dates before 1583 ;)

    static const int64_t LEAP_YEARS_IN_CYCLE = 97;
    static const int64_t LEAP_YEARS_UNTIL_1970 = 478;

    *out_is_leap = ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0);

    int cycles = year / 400;
    int years_since_cycle_start = year % 400;
    if (years_since_cycle_start < 0) {
        --cycles;
        years_since_cycle_start += 400;
    }

    int leap_years_since_cycle_start = (*out_is_leap ? 0 : 1)
                                       + years_since_cycle_start / 4
                                       - years_since_cycle_start / 100;
    int64_t leap_years_since_1970 = cycles * LEAP_YEARS_IN_CYCLE
                                    + leap_years_since_cycle_start
                                    - LEAP_YEARS_UNTIL_1970;
    return (year - 1970) * 365 + leap_years_since_1970;
}

static int month_to_days(int month, bool is_leap) {
    static const uint16_t MONTH_LENGTHS[] = {
        31, 28 /* or 29 */, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    int days = (is_leap && month > 2) ? 1 : 0;
    for (int i = 0; i < month - 1; ++i) {
        days += MONTH_LENGTHS[i];
    }
    return days;
}

avs_time_real_t
_avs_crypto_mbedtls_x509_time_to_avs_time(const mbedtls_x509_time *x509_time) {
    // Since Mbed TLS 3.0, mbedtls_x509_time is totally private, but there are
    // no public APIs to examine it in any other way than checking whether it's
    // in the future or in the past, so...
    if (x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(mon) < 1
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(mon) > 12
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(day) < 1
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(day) > 31
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(hour) < 0
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(hour) > 23
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(min) < 0
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(min) > 59
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(sec) < 0
            || x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(sec)
                           > 60 /* support leap seconds */) {
        return AVS_TIME_REAL_INVALID;
    }
    bool is_leap;
    int64_t days =
            year_to_days(x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(year),
                         &is_leap)
            + month_to_days(x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(mon),
                            is_leap)
            + x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(day) - 1;
    int64_t time =
            60
                    * (60 * x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(hour)
                       + x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(min))
            + x509_time->MBEDTLS_PRIVATE_BETWEEN_30_31(sec);
    return (avs_time_real_t) {
        .since_real_epoch.seconds = days * 86400 + time
    };
}

#    ifdef AVS_UNIT_TESTING
#        include "tests/crypto/mbedtls/mbedtls_private.c"
#    endif // AVS_UNIT_TESTING

#endif // defined(AVS_COMMONS_WITH_AVS_CRYPTO) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_ADVANCED_FEATURES) &&
       // defined(AVS_COMMONS_WITH_AVS_CRYPTO_PKI) &&
       // defined(AVS_COMMONS_WITH_MBEDTLS)
