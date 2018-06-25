#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
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
