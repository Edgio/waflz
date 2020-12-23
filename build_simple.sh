#!/bin/bash
# ------------------------------------------------------------------------------
# To build...
# ------------------------------------------------------------------------------
which cmake || {
    echo "Failed to find all required apps to build (cmake)."
    exit 1
}
# This is necessary in scenarios where the URL of the remote for a given submodule has changed.
git submodule sync || {
    echo "FAILED TO SYNC IS2 LIB"
    exit 1
}
git submodule update -f --init || {
    echo "FAILED TO UPDATE TO LATEST IS2 LIB"
    exit 1
}
mkdir -p build
pushd build && \
    cmake ../ \
    -DBUILD_APPS=ON \
    -DBUILD_TESTS=OFF && \
    make 
	popd && \
exit $?
