#!/usr/bin/env bash

pushd cmake-build-debug/unittests
make all
for i in *_test; do
    echo Running $i
    ./$i > /dev/null
    if test $? -ne 0; then
        echo "Test $i failed, re-run with output"
        ./$i
        exit 1
    fi
done
rm -f *.dat     # cleanup test files if all tests succeed

popd