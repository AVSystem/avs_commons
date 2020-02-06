/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

VISIBILITY_PRIVATE_HEADER_BEGIN

static int
AVS_CONCAT(unit_conv_, SCALAR_TYPE, _int64_t)(SCALAR_TYPE *output,
                                              int64_t input,
                                              unit_conv_op_t operation,
                                              int64_t factor) {
    assert(factor > 0);
    switch (operation) {
    case UCO_MUL:
        return AVS_CONCAT(safe_mul_, SCALAR_TYPE)(output, (SCALAR_TYPE) input,
                                                  (SCALAR_TYPE) factor);
    case UCO_DIV:
        *output = (SCALAR_TYPE) input / (SCALAR_TYPE) factor;
        return 0;
    default:
        AVS_UNREACHABLE("Invalid unit_conv operation");
        return -1;
    }
}

static inline int AVS_CONCAT(unit_conv_forward_, SCALAR_TYPE, _int64_t)(
        SCALAR_TYPE *output, int64_t input, const unit_conv_t *conv) {
    return AVS_CONCAT(unit_conv_, SCALAR_TYPE,
                      _int64_t)(output, input, conv->operation, conv->factor);
}

static inline int AVS_CONCAT(unit_conv_backward_, SCALAR_TYPE, _int64_t)(
        SCALAR_TYPE *output, int64_t input, const unit_conv_t *conv) {
    return AVS_CONCAT(unit_conv_, SCALAR_TYPE, _int64_t)(
            output, input, conv->operation == UCO_DIV ? UCO_MUL : UCO_DIV,
            conv->factor);
}

static int AVS_CONCAT(time_conv_forward_,
                      SCALAR_TYPE)(SCALAR_TYPE *output,
                                   int64_t seconds,
                                   int32_t nanoseconds,
                                   const time_conv_t *conv) {
    SCALAR_TYPE converted_s;
    SCALAR_TYPE converted_ns;
    if (seconds < 0 && nanoseconds > 0) {
        /* if the time is near the range limit,
           the negative value of seconds alone might be actually
           _out_ of range */
        ++seconds;
        nanoseconds -= NS_IN_S;
    }
    if (AVS_CONCAT(unit_conv_forward_, SCALAR_TYPE,
                   _int64_t)(&converted_s, seconds, &conv->conv_s)
            || AVS_CONCAT(unit_conv_forward_, SCALAR_TYPE, _int64_t)(
                       &converted_ns, nanoseconds, &conv->conv_ns)) {
        return -1;
    }
    return AVS_CONCAT(safe_add_, SCALAR_TYPE)(output, converted_s,
                                              converted_ns);
}

static int AVS_CONCAT(time_conv_backward_,
                      SCALAR_TYPE)(avs_time_duration_t *output,
                                   SCALAR_TYPE input,
                                   const time_conv_t *conv) {
    SCALAR_TYPE seconds_only;
    int64_t output_ns_tmp;
    if (AVS_CONCAT(unit_conv_backward_int64_t_,
                   SCALAR_TYPE)(&output->seconds, input, &conv->conv_s)
            || AVS_CONCAT(unit_conv_forward_, SCALAR_TYPE, _int64_t)(
                       &seconds_only, output->seconds, &conv->conv_s)
            || AVS_CONCAT(unit_conv_backward_int64_t_, SCALAR_TYPE)(
                       &output_ns_tmp, input - seconds_only, &conv->conv_ns)
            || output_ns_tmp <= -NS_IN_S || output_ns_tmp >= NS_IN_S) {
        return -1;
    }
    output->nanoseconds = (int32_t) output_ns_tmp;
    return normalize(output);
}

#undef SCALAR_TYPE

VISIBILITY_PRIVATE_HEADER_END
