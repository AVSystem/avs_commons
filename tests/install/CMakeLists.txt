# Copyright 2025 AVSystem <avsystem@avsystem.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.16.0)
project(avs_commons C)

find_package(avs_commons REQUIRED)

foreach(TGT ${TARGETS_TO_CHECK})
    if(TARGET "${TGT}")
        message(STATUS "Found target: ${TGT}")
    else()
        message(FATAL_ERROR "Target ${TGT} not created by find_package")
    endif()
endforeach()
