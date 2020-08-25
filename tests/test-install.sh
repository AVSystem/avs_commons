#!/usr/bin/env bash
# Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
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

set -e

canonicalize() {
    echo "$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
}

SCRIPT_DIR="$(dirname "$(canonicalize "$0")")"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

list_targets() {
    local BUILD_DIR
    BUILD_DIR="$1"

    make -C "$BUILD_DIR" help \
        | sed -e 's/^... //' \
        | grep avs_ \
        | grep -v _test$ \
        | grep -v _check$ \
        | grep -v _doc$
}

test_install() {
    # test_install test_project_dir configure_command...
    local TEST_PROJECT
    TEST_PROJECT="$1"
    shift

    local TEMP_DIR
    TEMP_DIR="$(mktemp -d)"

    pushd "$TEMP_DIR"
        mkdir -p build
        pushd build
            "$@" -DCMAKE_INSTALL_PREFIX="$TEMP_DIR/install"
            cmake --build . -- install
        popd

        cmake -Davs_commons_DIR="$PWD/install/lib/avs_commons" \
              -DTARGETS_TO_CHECK="$(list_targets "$TEMP_DIR/build" | paste -sd\;)" \
              "$TEST_PROJECT"
    popd

    rm -rf "$TEMP_DIR"
}

for ARG; do
    test_install "$ARG" cmake "$ROOT_DIR"
    test_install "$ARG" "$ROOT_DIR/devconfig"
done
