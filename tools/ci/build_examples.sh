# !/bin/bash

build_example () {
    local example_dir=$(dirname "$1")

    # jump into project root directry
    cd $example_dir

    rm sdkconfig
    idf.py build
}

EXAMPLE_PATHS=$( find ${CI_PROJECT_DIR}/examples/ -type f -name Makefile | grep -v "/components/" | grep -v "/common_components/" | grep -v "/main/" | grep -v "/build_system/cmake/" | sort )

for FN in $EXAMPLE_PATHS
do
    build_example "$FN" || exit 1
done
